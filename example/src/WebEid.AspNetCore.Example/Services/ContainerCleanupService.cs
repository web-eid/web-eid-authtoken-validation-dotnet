// Copyright (c) 2026-2026 Estonian Information System Authority
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
