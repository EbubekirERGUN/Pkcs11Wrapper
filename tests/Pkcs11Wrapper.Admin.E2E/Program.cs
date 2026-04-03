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

        void LogStep(string message)
        {
            string entry = $"{DateTimeOffset.UtcNow:O} | {message}";
            eventLog.Add(entry);
            Console.WriteLine(entry);
        }

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
                await LoginAsync(page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "01-login.png"));

                await ExerciseUsersAsync(browser, page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "02-users.png"));

                await ExerciseDevicesAsync(page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "03-devices.png"));

                await ExerciseSlotsAsync(page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "04-slots.png"));

                await ExerciseKeysAsync(page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "05-keys.png"));

                await ExerciseLabAsync(page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "06-lab.png"));

                await ExerciseTelemetryAsync(page, config, eventLog, LogStep);
                await SaveScreenshotAsync(page, Path.Combine(config.ArtifactRoot, "07-telemetry.png"));

                await TryStopTracingAsync(context, config.ArtifactRoot, LogStep);
            }
            catch (Exception ex)
            {
                LogStep($"Failure: {ex.GetType().Name}: {ex.Message}");
                await WriteFailureDiagnosticsAsync(config.ArtifactRoot, eventLog, consoleOutput, pageErrors, requestFailures, ex, page);
                await TryCaptureFailureArtifactsAsync(page, config.ArtifactRoot, LogStep);
                await TryStopTracingAsync(context, config.ArtifactRoot, LogStep);
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

    private static async Task LoginAsync(IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Login: navigating to login page");
        await page.GotoAsync($"{config.BaseUrl}/login", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 15000 });
        await WaitForVisibleAsync(page, "[data-testid='login-username']");
        await WaitForInteractiveSettleAsync();
        await TypeAndBlurAsync(page, "[data-testid='login-username']", config.UserName);
        await TypeAndBlurAsync(page, "[data-testid='login-password']", config.Password);
        await Task.WhenAll(
            page.WaitForURLAsync(new Regex($"^{Regex.Escape(config.BaseUrl.TrimEnd('/'))}/?$", RegexOptions.IgnoreCase), new PageWaitForURLOptions { Timeout = 15000 }),
            page.ClickAsync("[data-testid='login-submit']"));
        await WaitForVisibleAsync(page, "[data-testid='nav-devices']");
        await WaitForInteractiveSettleAsync();
        logStep("Login: authenticated successfully");
    }

    private static async Task ExerciseUsersAsync(IBrowser browser, IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Users: creating a local user and verifying immediate fresh-context login");
        await NavigateToAsync(page, config.BaseUrl, "/users");

        string localUserName = $"ci-user-{DateTimeOffset.UtcNow:HHmmssfff}";
        string localPassword = "TempUser!Pass123";

        await page.ClickAsync("[data-testid='users-create-username']");
        await page.Locator("[data-testid='users-create-username']").PressSequentiallyAsync(localUserName);
        await page.ClickAsync("[data-testid='users-create-password']");
        await page.Locator("[data-testid='users-create-password']").PressSequentiallyAsync(localPassword);
        await page.ClickAsync("[data-testid='users-create-submit']");
        await WaitForTextAsync(page.Locator("[data-testid='users-status']"), "Local user created.", 15000);
        await WaitForTextAsync(page.Locator("table"), localUserName, 15000);

        IBrowserContext freshContext = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true,
            ViewportSize = new ViewportSize { Width = 1600, Height = 1000 }
        });

        try
        {
            IPage freshPage = await freshContext.NewPageAsync();
            await freshPage.GotoAsync($"{config.BaseUrl}/login", new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 15000 });
            await WaitForVisibleAsync(freshPage, "[data-testid='login-username']");
            await TypeAndBlurAsync(freshPage, "[data-testid='login-username']", localUserName);
            await TypeAndBlurAsync(freshPage, "[data-testid='login-password']", localPassword);
            await Task.WhenAll(
                freshPage.WaitForURLAsync(new Regex($"^{Regex.Escape(config.BaseUrl.TrimEnd('/'))}/?$", RegexOptions.IgnoreCase), new PageWaitForURLOptions { Timeout = 15000 }),
                freshPage.ClickAsync("[data-testid='login-submit']"));
            await WaitForVisibleAsync(freshPage, "[data-testid='nav-devices']");
        }
        finally
        {
            await freshContext.CloseAsync();
        }

        logStep($"Users: created '{localUserName}' and confirmed immediate login in a fresh browser context");
    }

    private static async Task ExerciseDevicesAsync(IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Devices: creating CI device profile");
        await NavigateToAsync(page, config.BaseUrl, "/devices");
        string uiDeviceName = $"{config.DeviceName} UI {DateTimeOffset.UtcNow:HHmmssfff}";
        await page.FillAsync("[data-testid='device-name']", uiDeviceName);
        await page.FillAsync("[data-testid='device-module-path']", config.ModulePath);
        await page.FillAsync("[data-testid='device-token-label']", config.TokenLabel);
        await page.FillAsync("[data-testid='device-notes']", "CI runtime E2E device profile");
        await page.ClickAsync("[data-testid='device-save']");
        await WaitForTextAsync(page.Locator("[data-testid='devices-status']"), $"Saved device '{uiDeviceName}'.", 15000);

        ILocator rows = page.Locator("[data-testid='devices-table'] tbody tr");
        await WaitForCountAtLeastAsync(rows, 2, 15000);
        await WaitForTextAsync(page.Locator("[data-testid='devices-table']"), uiDeviceName, 15000);
        logStep("Devices: save + inventory view passed");
    }

    private static async Task ExerciseSlotsAsync(IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Slots: verifying slot inventory surface");
        await NavigateToAsync(page, config.BaseUrl, "/slots");
        await WaitForVisibleAsync(page, "[data-testid='slots-device']");
        await WaitForTextAsync(page.Locator("[data-testid='slots-device']"), config.DeviceName, 15000);
        await WaitForVisibleAsync(page, "[data-testid='slots-load']");
        await page.SelectOptionAsync("[data-testid='slots-device']", new[] { new SelectOptionValue { Label = config.DeviceName } });
        await page.ClickAsync("[data-testid='slots-load']");
        await WaitForTextAsync(page.Locator("[data-testid='slots-status']"), "Loaded ", 15000);
        await WaitForCountAtLeastAsync(page.Locator("[data-testid='slots-table'] tbody tr"), 1, 15000);

        ILocator setupRequiredRows = page.Locator("[data-testid='slots-table'] tbody tr").Filter(new LocatorFilterOptions
        {
            Has = page.Locator("span:has-text('Setup required')")
        });

        await WaitForCountAtLeastAsync(setupRequiredRows, 1, 15000);
        ILocator setupRequiredRow = setupRequiredRows.First;
        await WaitForTextAsync(setupRequiredRow, "not initialized", 15000);

        if (!await setupRequiredRow.Locator("button:has-text('Open RO')").IsDisabledAsync())
        {
            throw new InvalidOperationException("Expected the Setup required slot to disable the Open RO action.");
        }

        if (!await setupRequiredRow.Locator("button:has-text('Open RW')").IsDisabledAsync())
        {
            throw new InvalidOperationException("Expected the Setup required slot to disable the Open RW action.");
        }

        logStep("Slots: loaded inventory and verified setup-required slots are not directly actionable");
    }

    private static async Task ExerciseKeysAsync(IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Keys: loading object inventory and opening detail");
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
        logStep("Keys: loaded filtered objects and opened detail panel");
    }

    private static async Task ExerciseLabAsync(IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Lab: running bounded FindObjects operation");
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
        logStep("Lab: FindObjects executed successfully");
    }

    private static async Task ExerciseTelemetryAsync(IPage page, TestConfig config, List<string> eventLog, Action<string> logStep)
    {
        logStep("Telemetry: refreshing, filtering, and checking operator summaries");
        await NavigateToAsync(page, config.BaseUrl, "/telemetry");
        await page.ClickAsync("[data-testid='telemetry-refresh']");
        await WaitForCountAtLeastAsync(page.Locator("[data-testid='telemetry-table'] tbody tr"), 1, 20000);
        await WaitForVisibleAsync(page, "[data-testid='telemetry-trend']");
        await WaitForCountAtLeastAsync(page.Locator("[data-testid='telemetry-top-operations'] tbody tr"), 1, 20000);
        await page.SelectOptionAsync("[data-testid='telemetry-device-filter']", new[] { new SelectOptionValue { Label = config.DeviceName } });
        await page.FillAsync("[data-testid='telemetry-search']", "C_FindObjects");
        await page.FillAsync("[data-testid='telemetry-min-duration']", "0");
        await page.PressAsync("[data-testid='telemetry-min-duration']", "Tab");
        await WaitForTextAsync(page.Locator("[data-testid='telemetry-table']"), config.DeviceName, 20000);
        await WaitForTextAsync(page.Locator("[data-testid='telemetry-table']"), "C_FindObjects", 20000);
        await WaitForAnyTextAsync(page.Locator("[data-testid='telemetry-top-operations']"), 20000, "VisitObjects", "FindObjects");
        logStep("Telemetry: verified filtered PKCS#11 event stream plus operator summary widgets");
    }

    private static async Task NavigateToAsync(IPage page, string baseUrl, string expectedPath)
    {
        if (TryGetNavSelector(expectedPath, out string? navSelector))
        {
            Uri current = new(page.Url);
            if (!string.Equals(current.AbsolutePath, expectedPath, StringComparison.OrdinalIgnoreCase))
            {
                await WaitForVisibleAsync(page, navSelector!);
                await Task.WhenAll(
                    page.WaitForURLAsync($"{baseUrl}{expectedPath}", new PageWaitForURLOptions { Timeout = 15000 }),
                    page.ClickAsync(navSelector!));
            }
        }
        else
        {
            await page.GotoAsync($"{baseUrl}{expectedPath}", new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 15000
            });
        }

        await WaitForInteractiveSettleAsync();
    }

    private static bool TryGetNavSelector(string expectedPath, out string? navSelector)
    {
        navSelector = expectedPath switch
        {
            "/devices" => "[data-testid='nav-devices']",
            "/slots" => "[data-testid='nav-slots']",
            "/keys" => "[data-testid='nav-keys']",
            "/lab" => "[data-testid='nav-lab']",
            "/telemetry" => "[data-testid='nav-telemetry']",
            "/users" => "[data-testid='nav-users']",
            _ => null
        };

        return navSelector is not null;
    }

    private static async Task TypeAndBlurAsync(IPage page, string selector, string value)
    {
        ILocator locator = page.Locator(selector);
        await locator.ClickAsync();
        await locator.PressSequentiallyAsync(value);
        await locator.PressAsync("Tab");
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

    private static async Task WaitForAnyTextAsync(ILocator locator, int timeoutMs, params string[] expectedValues)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                if (await locator.IsVisibleAsync())
                {
                    string text = (await locator.TextContentAsync()) ?? string.Empty;
                    if (expectedValues.Any(expected => text.Contains(expected, StringComparison.OrdinalIgnoreCase)))
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
        throw new TimeoutException($"Timed out waiting for any of [{string.Join(", ", expectedValues)}]. Last text was: {last}");
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

    private static async Task TryCaptureFailureArtifactsAsync(IPage page, string artifactRoot, Action<string> logStep)
    {
        try
        {
            logStep("Failure capture: attempting viewport screenshot");
            await SaveScreenshotAsync(page, Path.Combine(artifactRoot, "failure.png"), fullPage: false, timeoutMs: 3000);
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-screenshot-error.txt"), ex.ToString());
        }

        try
        {
            logStep("Failure capture: writing DOM snapshot");
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-page.html"), await page.ContentAsync().WaitAsync(TimeSpan.FromSeconds(3)));
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-page-error.txt"), ex.ToString());
        }
    }

    private static async Task WriteFailureDiagnosticsAsync(
        string artifactRoot,
        List<string> eventLog,
        StringBuilder consoleOutput,
        StringBuilder pageErrors,
        StringBuilder requestFailures,
        Exception exception,
        IPage page)
    {
        await File.WriteAllTextAsync(Path.Combine(artifactRoot, "scenario.log"), string.Join(Environment.NewLine, eventLog));
        await File.WriteAllTextAsync(Path.Combine(artifactRoot, "browser-console.log"), consoleOutput.ToString());
        await File.WriteAllTextAsync(Path.Combine(artifactRoot, "browser-page-errors.log"), pageErrors.ToString());
        await File.WriteAllTextAsync(Path.Combine(artifactRoot, "browser-request-failures.log"), requestFailures.ToString());
        await File.WriteAllTextAsync(Path.Combine(artifactRoot, "exception.txt"), exception.ToString());

        try
        {
            string pageState = $"URL: {page.Url}{Environment.NewLine}Title: {await page.TitleAsync().WaitAsync(TimeSpan.FromSeconds(3))}{Environment.NewLine}";
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-page-state.txt"), pageState);
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "failure-page-state-error.txt"), ex.ToString());
        }
    }

    private static async Task TryStopTracingAsync(IBrowserContext context, string artifactRoot, Action<string> logStep)
    {
        try
        {
            logStep("Tracing: stopping and exporting trace");
            await context.Tracing.StopAsync(new TracingStopOptions
            {
                Path = Path.Combine(artifactRoot, "playwright-trace.zip")
            }).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex)
        {
            await File.WriteAllTextAsync(Path.Combine(artifactRoot, "trace-stop-error.txt"), ex.ToString());
        }
    }

    private static async Task SaveScreenshotAsync(IPage page, string path, bool fullPage = true, float timeoutMs = 10000)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = path,
            FullPage = fullPage,
            Timeout = timeoutMs
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
