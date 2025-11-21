// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.AspNetCore.Example.Services
{
    using System;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;

    public class ContainerCleanupService(ILogger<ContainerCleanupService> logger) : BackgroundService
    {
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan MaxFileAge = TimeSpan.FromHours(1);
        private readonly ILogger<ContainerCleanupService> logger = logger;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                DeleteOldContainerFiles();

                await Task.Delay(CleanupInterval, stoppingToken);
            }
        }

        private void DeleteOldContainerFiles()
        {
            var directory = Directory.GetCurrentDirectory();
            var threshold = DateTime.UtcNow - MaxFileAge;

            foreach (var file in Directory.EnumerateFiles(directory, "container_*"))
            {
                try
                {
                    var lastWriteTime = File.GetLastWriteTimeUtc(file);

                    if (lastWriteTime < threshold)
                    {
                        File.Delete(file);
#pragma warning disable CA1873
                        logger.LogInformation("Deleted old container file: {File}", file);
#pragma warning restore CA1873
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    logger.LogWarning(ex, "Failed to delete old container file: {File}", file);
                }
            }
        }
    }
}
