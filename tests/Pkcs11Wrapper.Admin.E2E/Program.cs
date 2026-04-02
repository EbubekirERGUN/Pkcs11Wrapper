using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

return await AdminRuntimeE2E.RunAsync();

internal static class AdminRuntimeE2E
{
    public static async Task<int> RunAsync()
    {
        TestConfig config;
        try
        {
            config = TestConfig.FromEnvironment();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }

        Directory.CreateDirectory(config.ArtifactRoot);
        List<string> eventLog = [];
        StringBuilder consoleOutput = new();
        StringBuilder pageErrors = new();
        StringBuilder requestFailures = new();

        try
        {
            using IPlaywright playwright = await Playwright.CreateAsync();
            await using IBrowser browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true
            });

            IBrowserContext context = await browser.NewContextAsync(new BrowserNewContextOptions
            {
                IgnoreHTTPSErrors = true,
                ViewportSize = new ViewportSize { Width = 1600, Height = 1000 }
            });

            await context.Tracing.StartAsync(new TracingStartOptions
            {
                Screenshots = true,
                Snapshots = true,
                Sources = true
            });

            IPage page = await context.NewPageAsync();
            page.Console += (_, message) => consoleOutput.AppendLine($"[{message.Type}] {message.Text}");
            page.PageError += (_, message) => pageErrors.AppendLine(message);
            page.RequestFailed += (_, request) => requestFailures.AppendLine($"{request.Method} {request.Url} :: {request.Failure}");

            try
            {
                await LoginAsync(page, config, eventLog);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "01-login.png"));

                await ExerciseDevicesAsync(page, config, eventLog);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "02-devices.png"));

                await ExerciseSlotsAsync(page, config, eventLog);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "03-slots.png"));

                await ExerciseKeysAsync(page, config, eventLog);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "04-keys.png"));

                await ExerciseLabAsync(page, config, eventLog);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "05-lab.png"));

                await ExerciseTelemetryAsync(page, config, eventLog);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "06-telemetry.png"));

                await context.Tracing.StopAsync(new TracingStopOptions
                {
                    Path = Path.Combine(config.ArtifactRoot, "playwright-trace.zip")
                });
            }
            catch
            {
                await TryCaptureFailureArtifactsAsync(page, config.ArtifactRoot);
                await context.Tracing.StopAsync(new TracingStopOptions
                {
                    Path = Path.Combine(config.ArtifactRoot, "playwright-trace.zip")
                });
                throw;
            }
            finally
            {
                await context.CloseAsync();
            }

            await File.WriteAllLinesAsync(Path.Combine(config.ArtifactRoot, "scenario.log"), eventLog);
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "browser-console.log"), consoleOutput.ToString());
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "browser-page-errors.log"), pageErrors.ToString());
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "browser-request-failures.log"), requestFailures.ToString());

            Console.WriteLine("Admin runtime E2E completed successfully.");
            return 0;
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "scenario.log"), string.Join(Environment.NewLine, eventLog));
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "browser-console.log"), consoleOutput.ToString());
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "browser-page-errors.log"), pageErrors.ToString());
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "browser-request-failures.log"), requestFailures.ToString());
            await File.WriteAllTextAsync(Path.Combine(config.ArtifactRoot, "exception.txt"), ex.ToString());
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static async Task LoginAsync(IPage page, TestConfig config, List<string> eventLog)
    {
        eventLog.Add("Login: navigating to login page");
        await page.GotoAsync($"{config.BaseUrl}/login", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 15000 });
        await WaitForVisibleAsync(page, "[data-testid='login-username']");
        await WaitForInteractiveSettleAsync();
        await page.FillAsync("[data-testid='login-username']", config.UserName);
        await page.FillAsync("[data-testid='login-password']", config.Password);
        await Task.WhenAll(
            page.WaitForURLAsync(new Regex($"^{Regex.Escape(config.BaseUrl.TrimEnd('/'))}/?$", RegexOptions.IgnoreCase), new PageWaitForURLOptions { Timeout = 15000 }),
            page.ClickAsync("[data-testid='login-submit']"));
        await WaitForVisibleAsync(page, "[data-testid='nav-devices']");
        await WaitForInteractiveSettleAsync();
        eventLog.Add("Login: authenticated successfully");
    }

    private static async Task ExerciseDevicesAsync(IPage page, TestConfig config, List<string> eventLog)
    {
        eventLog.Add("Devices: creating CI device profile");
        await NavigateToAsync(page, config.BaseUrl, "/devices");
        string uiDeviceName = $"{config.DeviceName} UI";
        await page.FillAsync("[data-testid='device-name']", uiDeviceName);
        await page.FillAsync("[data-testid='device-module-path']", config.ModulePath);
        await page.FillAsync("[data-testid='device-token-label']", config.TokenLabel);
        await page.FillAsync("[data-testid='device-notes']", "CI runtime E2E device profile");
        await page.ClickAsync("[data-testid='device-save']");
        await WaitForTextAsync(page.Locator("[data-testid='devices-status']"), $"Saved device '{uiDeviceName}'.", 15000);

        ILocator rows = page.Locator("[data-testid='devices-table'] tbody tr");
        await WaitForCountAtLeastAsync(rows, 2, 15000);
        await WaitForTextAsync(page.Locator("[data-testid='devices-table']"), uiDeviceName, 15000);
        eventLog.Add("Devices: save + inventory view passed");
    }

    private static async Task ExerciseSlotsAsync(IPage page, TestConfig config, List<string> eventLog)
    {
        eventLog.Add("Slots: verifying slot inventory surface");
        await NavigateToAsync(page, config.BaseUrl, "/slots");
        await WaitForVisibleAsync(page, "[data-testid='slots-device']");
        await WaitForTextAsync(page.Locator("[data-testid='slots-device']"), config.DeviceName, 15000);
        await WaitForVisibleAsync(page, "[data-testid='slots-load']");
        eventLog.Add("Slots: page loaded with seeded device context");
    }

    private static async Task ExerciseKeysAsync(IPage page, TestConfig config, List<string> eventLog)
    {
        eventLog.Add("Keys: loading object inventory and opening detail");
        await NavigateToAsync(page, config.BaseUrl, "/keys");
        await WaitForTextAsync(page.Locator("[data-testid='keys-device']"), config.DeviceName, 15000);
        await page.SelectOptionAsync("[data-testid='keys-device']", new[] { new SelectOptionValue { Label = config.DeviceName } });
        await WaitForOptionCountAtLeastAsync(page, "[data-testid='keys-slot'] option", 2, 15000);
        await SelectFirstNonEmptyOptionAsync(page, "[data-testid='keys-slot']");
        await page.FillAsync("[data-testid='keys-label-filter']", config.FindLabel);
        await page.FillAsync("[data-testid='keys-user-pin']", config.UserPin);
        await page.ClickAsync("[data-testid='keys-load']");
        await WaitForTextAsync(page.Locator("[data-testid='keys-status']"), "Loaded ", 15000);
        ILocator rows = page.Locator("[data-testid='keys-table'] tbody tr");
        await WaitForCountAtLeastAsync(rows, 1, 15000);
        await rows.First.Locator("button:has-text('Details')").ClickAsync();
        await WaitForVisibleAsync(page, "[data-testid='keys-detail-panel']");
        await WaitForTextAsync(page.Locator("[data-testid='keys-detail-panel']"), "Object detail", 15000);
        eventLog.Add("Keys: loaded filtered objects and opened detail panel");
    }

    private static async Task ExerciseLabAsync(IPage page, TestConfig config, List<string> eventLog)
    {
        eventLog.Add("Lab: running bounded FindObjects operation");
        await NavigateToAsync(page, config.BaseUrl, "/lab");
        await WaitForTextAsync(page.Locator("[data-testid='lab-device']"), config.DeviceName, 15000);
        await page.SelectOptionAsync("[data-testid='lab-device']", new[] { new SelectOptionValue { Label = config.DeviceName } });
        await page.SelectOptionAsync("[data-testid='lab-operation']", new[] { new SelectOptionValue { Value = "FindObjects" } });
        await WaitForVisibleAsync(page, "[data-testid='lab-slot']");
        await WaitForOptionCountAtLeastAsync(page, "[data-testid='lab-slot'] option", 2, 15000);
        await SelectFirstNonEmptyOptionAsync(page, "[data-testid='lab-slot']");
        await page.FillAsync("[data-testid='lab-user-pin']", config.UserPin);
        await page.FillAsync("[data-testid='lab-find-label-filter']", config.FindLabel);
        await page.ClickAsync("[data-testid='lab-run']");
        await WaitForTextAsync(page.Locator("[data-testid='lab-result-panel']"), "Success", 20000);
        await WaitForTextAsync(page.Locator("[data-testid='lab-result-panel']"), "Operation: FindObjects", 20000);
        eventLog.Add("Lab: FindObjects executed successfully");
    }

    private static async Task ExerciseTelemetryAsync(IPage page, TestConfig config, List<string> eventLog)
    {
        eventLog.Add("Telemetry: refreshing, filtering, and checking operator summaries");
        await NavigateToAsync(page, config.BaseUrl, "/telemetry");
        await page.ClickAsync("[data-testid='telemetry-refresh']");
        await WaitForCountAtLeastAsync(page.Locator("[data-testid='telemetry-table'] tbody tr"), 1, 20000);
        await WaitForVisibleAsync(page, "[data-testid='telemetry-trend']");
        await WaitForCountAtLeastAsync(page.Locator("[data-testid='telemetry-top-operations'] tbody tr"), 1, 20000);
        await page.SelectOptionAsync("[data-testid='telemetry-device-filter']", new[] { new SelectOptionValue { Label = config.DeviceName } });
        await page.FillAsync("[data-testid='telemetry-search']", "FindObjects");
        await page.FillAsync("[data-testid='telemetry-min-duration']", "0");
        await page.PressAsync("[data-testid='telemetry-min-duration']", "Tab");
        await WaitForTextAsync(page.Locator("[data-testid='telemetry-table']"), config.DeviceName, 20000);
        await WaitForTextAsync(page.Locator("[data-testid='telemetry-table']"), "FindObjects", 20000);
        await WaitForTextAsync(page.Locator("[data-testid='telemetry-top-operations']"), "FindObjects", 20000);
        eventLog.Add("Telemetry: verified filtered PKCS#11 event stream plus operator summary widgets");
    }

    private static async Task NavigateToAsync(IPage page, string baseUrl, string expectedPath)
    {
        await page.GotoAsync($"{baseUrl}{expectedPath}", new PageGotoOptions
        {
            WaitUntil = WaitUntilState.DOMContentLoaded,
            Timeout = 15000
        });
        await WaitForInteractiveSettleAsync();
    }

    private static Task WaitForInteractiveSettleAsync()
        => Task.Delay(1000);

    private static async Task SelectFirstNonEmptyOptionAsync(IPage page, string selectSelector)
    {
        string value = await page.Locator($"{selectSelector} option").EvaluateAllAsync<string>(@"options => {
            const usable = options.find(option => option.value && option.value.trim().length > 0);
            return usable ? usable.value : '';
        }");

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"No selectable option was available for '{selectSelector}'.");
        }

        await page.SelectOptionAsync(selectSelector, new[] { new SelectOptionValue { Value = value } });
    }

    private static async Task WaitForVisibleAsync(IPage page, string selector, int timeoutMs = 15000)
    {
        await page.Locator(selector).WaitForAsync(new LocatorWaitForOptions
        {
            State = WaitForSelectorState.Visible,
            Timeout = timeoutMs
        });
    }

    private static async Task WaitForTextAsync(ILocator locator, string expected, int timeoutMs)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                if (await locator.IsVisibleAsync())
                {
                    string text = (await locator.TextContentAsync()) ?? string.Empty;
                    if (text.Contains(expected, StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }
            }
            catch
            {
                // ignore transient re-render issues while polling
            }

            await Task.Delay(200);
        }

        string last = (await locator.TextContentAsync()) ?? string.Empty;
        throw new TimeoutException($"Timed out waiting for text '{expected}'. Last text was: {last}");
    }

    private static async Task WaitForCountAtLeastAsync(ILocator locator, int minimum, int timeoutMs)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await locator.CountAsync() >= minimum)
            {
                return;
            }

            await Task.Delay(200);
        }

        throw new TimeoutException($"Timed out waiting for at least {minimum} element(s).");
    }

    private static async Task WaitForOptionCountAtLeastAsync(IPage page, string selector, int minimum, int timeoutMs)
    {
        await WaitForCountAtLeastAsync(page.Locator(selector), minimum, timeoutMs);
    }

    private static async Task TryCaptureFailureArtifactsAsync(IPage page, string artifactRoot)
    {
        try
        {
            await SaveScreenshotAsync(page, Path.Combine(artifactRoot, "failure.png"));
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-screenshot-error.txt"), ex.ToString());
        }

        try
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-page.html"), await page.ContentAsync());
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-page-error.txt"), ex.ToString());
        }
    }

    private static async Task SaveScreenshotAsync(IPage page, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = path,
            FullPage = true,
            Timeout = 10000
        });
    }
}

internal sealed record TestConfig(
    string BaseUrl,
    string UserName,
    string Password,
    string DeviceName,
    string ModulePath,
    string TokenLabel,
    string UserPin,
    string FindLabel,
    string ArtifactRoot)
{
    public static TestConfig FromEnvironment()
        => new(
            Require("ADMIN_E2E_BASE_URL"),
            Require("ADMIN_E2E_USERNAME"),
            Require("ADMIN_E2E_PASSWORD"),
            Require("ADMIN_E2E_DEVICE_NAME"),
            Require("ADMIN_E2E_MODULE_PATH"),
            Require("ADMIN_E2E_TOKEN_LABEL"),
            Require("ADMIN_E2E_USER_PIN"),
            Require("ADMIN_E2E_FIND_LABEL"),
            Require("ADMIN_E2E_ARTIFACT_ROOT"));

    private static string Require(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Missing required environment variable '{name}'.");
        }

        return value.Trim();
    }
}
