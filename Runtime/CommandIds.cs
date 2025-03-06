namespace Autron.Commands
{
    /// <summary>
    /// Contains precomputed unique integer values for the commands.
    /// These values are stable across builds and help avoid hardcoding strings.
    /// </summary>
    public static class CommandIds
    {
        // Base
        public static readonly uint OpenCanvas = Compute("BASE", "OpenCanvas");
        public static readonly uint ResetBeamer = Compute("BASE", "ResetBeamer");
        
        // Calibration
        public static readonly uint GenerateGrid = Compute("CAL", "GenerateGrid");
        public static readonly uint PointSelected = Compute("CAL", "PointSelected");
        public static readonly uint PointCalibrated = Compute("CAL", "PointCalibrated");
        
        // Bullets
        public static readonly uint BulletDetected = Compute("BUL", "BulletDetected");
        public static readonly uint BulletSizeChanged = Compute("BUL", "BulletSizeChanged");
        public static readonly uint BulletColorChanged = Compute("BUL", "BulletColorChanged");

        // Beamer - Creation/Deletion
        public static readonly uint GenerateBeamerCanvases = Compute("B", "GenerateBeamerCanvases");
        
        // Shooting Point - Creation/Deletion
        public static readonly uint AddShootingPoint = Compute("SP", "AddShootingPoint");
        public static readonly uint RemoveShootingPoint = Compute("SP", "RemoveShootingPoint");
        public static readonly uint ClearShootingPoints = Compute("SP", "ClearShootingPoints");
        public static readonly uint SaveLayout = Compute("SP", "SaveLayout");
        public static readonly uint LoadLayout = Compute("SP", "LoadLayout");
        public static readonly uint UpdateLayout = Compute("SP", "UpdateLayout");
        public static readonly uint DeleteLayout = Compute("SP", "DeleteLayout");

        // Shooting Point - Loading Cover
        public static readonly uint LoadingCoverText = Compute("SP-LOAD", "LoadingCoverText");
        public static readonly uint LoadingCoverToggle = Compute("SP-LOAD", "LoadingCoverToggle");

        private static uint Compute(string domain, string commandName)
        {
            return ComputeCommandID(domain, commandName);
        }

        private static uint ComputeCommandID(string domain, string commandName)
        {
            var combined = $"command:{domain}:{commandName}";
            return CommandHash.ComputeHash(combined);
        }
    }

    /// <summary>
    /// Contains precomputed unique integer values for the targets.
    /// These values are stable across builds and help avoid hardcoding strings.
    /// </summary>
    public static class TargetIds
    {
        public static readonly uint All = Compute("All");
        public static readonly uint Base = Compute("Base");
        public static readonly uint Bullets = Compute("Bullets");
        public static readonly uint ShootingPoints = Compute("ShootingPoints");
        public static readonly uint Calibration = Compute("Calibration");
        public static readonly uint SubCalibration = Compute("SubCalibration");
        public static readonly uint Heatmap = Compute("Heatmap");
        public static readonly uint Alarm = Compute("Alarm");
        public static readonly uint Scenario = Compute("Scenario");
        public static readonly uint Logo = Compute("Logo");

        private static uint Compute(string targetName)
        {
            return ComputeCommandID(targetName);
        }

        private static uint ComputeCommandID(string targetName)
        {
            var combined = $"target:{targetName}";
            return CommandHash.ComputeHash(combined);
        }
    }
}
