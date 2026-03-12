using DLLHijackHunter.Models;
using Microsoft.Win32.TaskScheduler;

namespace DLLHijackHunter.Discovery;

public static class ScheduledTaskEnumerator
{
    public static List<DiscoveryContext> EnumerateScheduledTasks()
    {
        var results = new List<DiscoveryContext>();

        try
        {
            using var ts = new TaskService();
            if (ts.RootFolder != null)
            {
                EnumerateFolder(ts.RootFolder, results);
            }
        }
        catch { }

        return results;
    }

    private static void EnumerateFolder(TaskFolder folder, List<DiscoveryContext> results)
    {
        try
        {
            foreach (var task in folder.Tasks)
            {
                try
                {
                    if (task.Definition?.Actions == null) continue;

                    foreach (var action in task.Definition.Actions)
                    {
                        if (action is ExecAction execAction && !string.IsNullOrEmpty(execAction.Path))
                        {
                            string binaryPath = Environment.ExpandEnvironmentVariables(execAction.Path);
                            binaryPath = binaryPath.Trim('"');

                            if (!File.Exists(binaryPath)) continue;

                            string runAs = task.Definition.Principal?.UserId ?? "SYSTEM";
                            var logonType = task.Definition.Principal?.LogonType ?? TaskLogonType.ServiceAccount;
                            bool runsElevated = task.Definition.Principal?.RunLevel == TaskRunLevel.Highest;

                            // Determine repeat interval
                            TimeSpan? interval = null;
                            if (task.Definition.Triggers != null)
                            {
                                foreach (var trigger in task.Definition.Triggers)
                                {
                                    if (trigger.Repetition?.Interval != TimeSpan.Zero)
                                    {
                                        interval = trigger.Repetition?.Interval;
                                        break;
                                    }
                                }
                            }

                            bool isAutoStart = task.Definition.Triggers?.Any(t =>
                                t is BootTrigger || t is LogonTrigger) ?? false;

                            results.Add(new DiscoveryContext
                            {
                                BinaryPath = binaryPath,
                                TriggerType = TriggerType.ScheduledTask,
                                TriggerIdentifier = task.Path,
                                DisplayName = task.Name,
                                RunAsAccount = NormalizeTaskAccount(runAs, logonType),
                                IsAutoStart = isAutoStart,
                                RepeatInterval = interval
                            });
                        }
                    }
                }
                catch { continue; }
            }

            foreach (var subfolder in folder.SubFolders)
            {
                EnumerateFolder(subfolder, results);
            }
        }
        catch { }
    }

    private static string NormalizeTaskAccount(string account, TaskLogonType logonType)
    {
        if (string.IsNullOrEmpty(account)) return "NT AUTHORITY\\SYSTEM";

        if (logonType == TaskLogonType.ServiceAccount)
        {
            return account.ToUpperInvariant() switch
            {
                "SYSTEM" or "LOCALSYSTEM" => "NT AUTHORITY\\SYSTEM",
                "LOCAL SERVICE" => "NT AUTHORITY\\LOCAL SERVICE",
                "NETWORK SERVICE" => "NT AUTHORITY\\NETWORK SERVICE",
                _ => account
            };
        }

        return account;
    }
}