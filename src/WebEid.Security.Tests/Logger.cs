namespace WebEid.Security.Tests
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Extensions.Logging;

    public class Logger : ILogger
    {
        public Logger()
        {
            this.Logs = new List<string>();
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (!this.IsEnabled(logLevel))
            {
                return;
            }

            this.Logs.Add(formatter(state, exception));
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public IDisposable BeginScope<TState>(TState state) => default;

        public IList<string> Logs { get; private set; }
    }
}
