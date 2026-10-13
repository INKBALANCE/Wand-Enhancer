using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using WandEnhancer.Core.Patching.Shared;

namespace WandEnhancer.Core.Patching.Strategies.Static
{
    internal sealed class StaticStrategy : IPatchStrategy
    {
        private const string AuxiliaryDirectory = @"static\unpacked\auxiliary";
        private const string AuxiliarySearchPattern = "*AuxiliaryService.exe";

        public bool RequiresLauncherAlways => false;

        public void ApplyEnablement(PatchContext context)
        {
            // The integrity fuse stays enabled: Electron builds shipped with Wand 12.62.0 fail to
            // inject the trainer at game launch whenever the fuse is disabled. The expectation
            // embedded in the executable is re-pointed at the patched archive instead, so the
            // validation passes with the check left on.
            string asarPath = Path.Combine(Path.GetDirectoryName(context.UnpackedPath), "app.asar");
            string pristineAsarPath = asarPath + ".backup";

            if (!AsarIntegrityHashPatch.Apply(context.Install.ExecutablePath, asarPath, pristineAsarPath, context.Log))
            {
                throw new Exception($"[ENHANCER] Could not re-point the ASAR integrity hash in {Path.GetFileName(context.Install.ExecutablePath)}. The version may not be supported.");
            }

            // Heal an install whose fuse was disabled by an older patcher version or by hand.
            DiskFusePatch.EnsureEnabled(context.Install.ExecutablePath, context.Log);

            string aux = FindAuxiliary(context.UnpackedPath);
            if (aux == null)
            {
                context.Log?.Invoke("[ENHANCER] No auxiliary service found; skipping check.", ELogType.Info);
                return;
            }

            if (AuxTrustNeutralizer.Neutralize(aux, context.Log) < 0)
            {
                throw new Exception("[ENHANCER] Could not neutralise the auxiliary service trust check; it would reject the patched Wand.");
            }
        }

        public bool Launch(PatchContext context, string args)
        {
            try
            {
                // dispose handle; process keeps running
                Process.Start(new ProcessStartInfo(context.Install.ExecutablePath, args ?? string.Empty)
                {
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(context.Install.ExecutablePath)
                })?.Dispose();
                return true;
            }
            catch (Exception e)
            {
                context.Log?.Invoke($"Could not start Wand: {e.Message}", ELogType.Error);
                return false;
            }
        }

        private static string FindAuxiliary(string unpackedPath)
        {
            if (string.IsNullOrEmpty(unpackedPath))
            {
                return null;
            }

            string directory = Path.Combine(unpackedPath, AuxiliaryDirectory);
            return Directory.Exists(directory)
                ? Directory.EnumerateFiles(directory, AuxiliarySearchPattern).FirstOrDefault()
                : null;
        }
    }
}
