using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WandEnhancer.Core.Patching.Shared
{
    /// <summary>
    /// Re-points the ASAR header hash embedded in the executable at the patched archive.
    /// Electron validates app.asar's header against that hash while the integrity fuse is
    /// enabled, and that enabled state is what keeps trainer injection working at game
    /// launch: Electron builds shipped with Wand 12.62.0 fail to inject when the fuse is
    /// disabled, whatever value disables it. The patch therefore rewrites the expectation
    /// instead of switching the check off.
    /// </summary>
    internal static class AsarIntegrityHashPatch
    {
        private const string BackupSuffix = ".integritybak";
        private const int HashLength = 64;

        // electron-builder embeds an integrity list, e.g.
        //   [{"file":"resources\\app.asar","alg":"SHA256","value":"<64 hex>"}]
        // How the archive path is escaped varies between builds, so the search anchors on the
        // shape that carries no backslashes and checks the context for the archive name instead.
        private static readonly byte[] ValueMarker = Encoding.ASCII.GetBytes("\"alg\":\"SHA256\",\"value\":\"");

        /// <summary>Overwrites the embedded expected header hash with the patched archive's.</summary>
        /// <returns>False when the embedding or the archive header could not be read.</returns>
        public static bool Apply(string exePath, string patchedAsarPath, string pristineAsarPath,
            Action<string, ELogType> log)
        {
            string patchedHash = ComputeHeaderHash(patchedAsarPath);
            if (patchedHash == null)
            {
                log?.Invoke($"[ENHANCER] Could not read the header of {Path.GetFileName(patchedAsarPath)}.", ELogType.Error);
                return false;
            }

            byte[] image;
            try
            {
                image = File.ReadAllBytes(exePath);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                log?.Invoke($"[ENHANCER] Could not read {Path.GetFileName(exePath)}: {e.Message}", ELogType.Error);
                return false;
            }

            long valueOffset = FindEmbeddedHashOffset(image, pristineAsarPath);
            if (valueOffset < 0)
            {
                log?.Invoke($"[ENHANCER] No embedded ASAR integrity hash found in {Path.GetFileName(exePath)}.", ELogType.Error);
                return false;
            }

            string previous = Encoding.ASCII.GetString(image, (int)valueOffset, HashLength);
            if (!IsHex(previous))
            {
                log?.Invoke("[ENHANCER] The embedded ASAR integrity hash has an unexpected format.", ELogType.Error);
                return false;
            }

            string backup = exePath + BackupSuffix;
            if (!File.Exists(backup))
            {
                File.WriteAllText(backup, previous);
            }

            using (var stream = new FileStream(exePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                stream.Position = valueOffset;
                byte[] value = Encoding.ASCII.GetBytes(patchedHash);
                stream.Write(value, 0, value.Length);
            }

            log?.Invoke("[ENHANCER] Embedded ASAR integrity hash re-pointed at the patched archive.", ELogType.Info);
            return true;
        }

        /// <summary>Best-effort restore of the shipped embedded hash. Does not throw.</summary>
        public static void Remove(string exePath, Action<string, ELogType> log)
        {
            string backup = exePath + BackupSuffix;
            if (!File.Exists(backup))
            {
                return;
            }

            try
            {
                string original = File.ReadAllText(backup).Trim();
                if (original.Length == HashLength && IsHex(original))
                {
                    byte[] image = File.ReadAllBytes(exePath);
                    long valueOffset = FindEmbeddedHashOffset(image, null);
                    if (valueOffset >= 0)
                    {
                        using (var stream = new FileStream(exePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
                        {
                            stream.Position = valueOffset;
                            byte[] value = Encoding.ASCII.GetBytes(original);
                            stream.Write(value, 0, value.Length);
                        }

                        log?.Invoke($"[ENHANCER] Embedded ASAR integrity hash restored in {Path.GetFileName(exePath)}.", ELogType.Info);
                    }
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                log?.Invoke($"[ENHANCER] The embedded ASAR integrity hash could not be restored: {e.Message}. " +
                            "Use Restore again after closing Wand.", ELogType.Warn);
                return;
            }

            File.Delete(backup);
        }

        /// <summary>Locates the 64-hex value inside the executable, by embedding shape first.</summary>
        private static long FindEmbeddedHashOffset(byte[] image, string pristineAsarPath)
        {
            long marker = IndexOf(image, ValueMarker, 0);
            while (marker >= 0)
            {
                long valueOffset = marker + ValueMarker.Length;
                if (valueOffset + HashLength <= image.LongLength && LooksLikeArchiveEntry(image, marker))
                {
                    string candidate = Encoding.ASCII.GetString(image, (int)valueOffset, HashLength);
                    if (IsHex(candidate))
                    {
                        return valueOffset;
                    }
                }

                marker = IndexOf(image, ValueMarker, marker + 1);
            }

            // Unknown embedding shape: fall back to the shipped value, which is the header
            // hash of the pristine archive this run started from.
            if (!string.IsNullOrEmpty(pristineAsarPath) && File.Exists(pristineAsarPath))
            {
                string pristineHash = ComputeHeaderHash(pristineAsarPath);
                if (pristineHash != null)
                {
                    byte[] needle = Encoding.ASCII.GetBytes(pristineHash);
                    long hashAt = IndexOf(image, needle, 0);
                    if (hashAt >= 0)
                    {
                        return hashAt;
                    }
                }
            }

            return -1;
        }

        /// <summary>The embedding's file name mentions the archive within a short window before the value.</summary>
        private static bool LooksLikeArchiveEntry(byte[] image, long marker)
        {
            int windowStart = (int)Math.Max(0, marker - 160);
            int windowLength = (int)(marker - windowStart);
            string context = Encoding.ASCII.GetString(image, windowStart, windowLength);
            return context.IndexOf("app.asar", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>SHA-256 of the archive's header JSON, as Electron computes it.</summary>
        private static string ComputeHeaderHash(string asarPath)
        {
            try
            {
                using (var stream = new FileStream(asarPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var prefix = new byte[16];
                    if (!ReadFull(stream, prefix))
                    {
                        return null;
                    }

                    uint headerSize = BitConverter.ToUInt32(prefix, 4);
                    long dataOffset = 8 + headerSize;
                    if (headerSize == 0 || dataOffset > stream.Length)
                    {
                        return null;
                    }

                    // The header JSON follows the pickle fields; builds differ in whether
                    // the length prefix sits at 8 or 12, so both layouts are accepted.
                    foreach (var candidate in new[] { new[] { 16, 12 }, new[] { 12, 8 } })
                    {
                        int jsonStart = candidate[0];
                        uint length = BitConverter.ToUInt32(prefix, candidate[1]);
                        if (length == 0 || jsonStart + length > dataOffset)
                        {
                            continue;
                        }

                        stream.Position = jsonStart;
                        var json = new byte[length];
                        if (!ReadFull(stream, json) || json[0] != (byte)'{')
                        {
                            continue;
                        }

                        using (var sha = SHA256.Create())
                        {
                            return ToLowerHex(sha.ComputeHash(json));
                        }
                    }
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                return null;
            }

            return null;
        }

        private static long IndexOf(byte[] haystack, byte[] needle, long start)
        {
            for (long i = Math.Max(0, start); i <= haystack.LongLength - needle.Length; i++)
            {
                if (haystack[i] != needle[0])
                {
                    continue;
                }

                bool match = true;
                for (int j = 1; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    return i;
                }
            }

            return -1;
        }

        private static bool ReadFull(FileStream stream, byte[] buffer)
        {
            int read = 0;
            while (read < buffer.Length)
            {
                int chunk = stream.Read(buffer, read, buffer.Length - read);
                if (chunk <= 0)
                {
                    return false;
                }

                read += chunk;
            }

            return true;
        }

        private static bool IsHex(string value)
        {
            if (value.Length != HashLength)
            {
                return false;
            }

            foreach (char c in value)
            {
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!ok)
                {
                    return false;
                }
            }

            return true;
        }

        private static string ToLowerHex(byte[] hash)
        {
            var builder = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash)
            {
                builder.Append(b.ToString("x2"));
            }

            return builder.ToString();
        }
    }
}