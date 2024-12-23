// File: MainWindow.xaml.cs
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Text;
using System.ComponentModel;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using static OffboardMDEDevice.MainWindow;

namespace OffboardMDEDevice
{
    public partial class MainWindow : Window
    {
        private string? appSecret;
        private string? appRefreshToken;
        private string appClientId = "79d5aeee-e34d-434c-9c4c-a25f18f844b9";
        private string appTenantId = "3376fd25-ade9-423f-99d5-058e6d4214c3";
        private List<Customer>? allCustomers;
        private List<Device>? allDevices;
        private string? signedInUsername;
        private GridViewColumnHeader? _lastHeaderClicked = null;
        private ListSortDirection? _lastDirection = ListSortDirection.Ascending;
        private Dictionary<string, string>? _lastOffboardActions;
        private string? selectedCustomerId;

        //Classes for resourceTypes
        public class Customer
        {
            public string ?Id { get; set; }
            public string ?Name { get; set; }

            public override string ToString()
            {
                return $"{Name} ({Id})";
            }
        }
        public class Device
        {
            public string ?Id { get; set; }
            public string ?Name { get; set; }
            public string ?LastSeen { get; set; }
            public string ?LastOffboardAction { get; set; }
        }
        //Main 
        public MainWindow()
        {
            InitializeComponent();
        }
        //BackEnd Functions
        private async Task<string> GetCspTokenAsync(string refreshToken, string appSecret)
        {
            string appId = appClientId;
            string scope = "https://api.partnercenter.microsoft.com";
            string grantType = "refresh_token";

            var azureAdToken = await GetAzureAdTokenAsync(refreshToken, appId, appSecret, scope, grantType);
            return await GetPartnerCenterTokenAsync(azureAdToken);
        }
        private async Task<string> GetAzureAdTokenAsync(string refreshToken, string appId, string appSecret, string scope, string grantType)
        {
            var httpClient = HttpClientSingleton.Instance;
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", appId),
                new KeyValuePair<string, string>("resource", scope),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("grant_type", grantType),
                new KeyValuePair<string, string>("client_secret", appSecret)
            });

            var response = await httpClient.PostAsync("https://login.microsoftonline.com/3376fd25-ade9-423f-99d5-058e6d4214c3/oauth2/token", content);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var jsonResponse = JObject.Parse(responseContent);
            return jsonResponse["access_token"].ToString();
        }
        private async Task<string> GetPartnerCenterTokenAsync(string azureAdToken)
        {
            var httpClient = HttpClientSingleton.Instance;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", azureAdToken);
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "jwt_token")
            });

            var response = await httpClient.PostAsync("https://api.partnercenter.microsoft.com/generatetoken", content);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var jsonResponse = JObject.Parse(responseContent);
            return jsonResponse["access_token"].ToString();
        }
        private async Task<string> RetrieveSecretFromKeyVaultAsync(string secretName, InteractiveBrowserCredential credential)
        {
            var secretClient = new SecretClient(new Uri("https://abt-csp-keyvault.vault.azure.net/"), credential);
            KeyVaultSecret secret = await secretClient.GetSecretAsync(secretName);
            return secret.Value;
        }
        private async Task<List<Customer>> GetCspCustomersAsync(string cspToken)
        {
            var customers = new List<Customer>();
            var httpClient = HttpClientSingleton.Instance;
            string baseUrl = "https://api.partnercenter.microsoft.com";
            string nextLink = "/v1/customers";

            while (!string.IsNullOrEmpty(nextLink))
            {
                // Ensure nextLink starts with /v1
                if (!nextLink.StartsWith("/v1"))
                {
                    nextLink = $"/v1{nextLink}";
                }

                var requestUri = new Uri(new Uri(baseUrl), nextLink);
                Debug.WriteLine($"Requesting URL: {requestUri}");

                var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cspToken);

                var response = await httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var responseContent = await response.Content.ReadAsStringAsync();
                var jsonResponse = JObject.Parse(responseContent);
                foreach (var item in jsonResponse["items"])
                {
                    var companyProfile = item["companyProfile"] as JObject;
                    var companyName = companyProfile?["companyName"]?.ToString() ?? "Unknown Company";

                    customers.Add(new Customer
                    {
                        Id = item["id"].ToString(),
                        Name = companyName
                    });
                }

                var nextLinkObject = jsonResponse["links"]?["next"] as JObject;
                if (nextLinkObject != null)
                {
                    var nextUri = nextLinkObject["uri"]?.ToString();
                    if (!string.IsNullOrEmpty(nextUri))
                    {
                        nextLink = nextUri;
                        if (nextLinkObject["headers"] is JArray headersArray)
                        {
                            foreach (var header in headersArray)
                            {
                                if (header["key"]?.ToString() == "MS-ContinuationToken")
                                {
                                    var continuationToken = header["value"]?.ToString();
                                    if (!string.IsNullOrEmpty(continuationToken))
                                    {
                                        httpClient.DefaultRequestHeaders.Remove("MS-ContinuationToken");
                                        httpClient.DefaultRequestHeaders.Add("MS-ContinuationToken", continuationToken);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        nextLink = null;
                    }
                }
                else
                {
                    nextLink = null;
                }
            }

            return customers;
        }
        private async Task<string> GetAppTokenAsync(string appId, string clientSecret, string tenantId, string scope)
        {
            var httpClient = HttpClientSingleton.Instance;
            var content = new FormUrlEncodedContent(new[]
            {
        new KeyValuePair<string, string>("client_id", appId),
        new KeyValuePair<string, string>("scope", scope),
        new KeyValuePair<string, string>("client_secret", clientSecret),
        new KeyValuePair<string, string>("grant_type", "client_credentials")
    });

            var response = await httpClient.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var jsonResponse = JObject.Parse(responseContent);
            return jsonResponse["access_token"].ToString();
        }
        private async Task<List<Device>> GetDevicesAsync(string customerId, string appToken)
        {
            var devices = new List<Device>();
            var httpClient = HttpClientSingleton.Instance;
            string requestUri = $"https://api.securitycenter.microsoft.com/api/machines";

            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", appToken);

            var response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var jsonResponse = JObject.Parse(responseContent);
            foreach (var item in jsonResponse["value"])
            {
                var computerDnsName = item["computerDnsName"]?.ToString();
                if (!string.IsNullOrEmpty(computerDnsName))
                {
                    var deviceId = item["id"].ToString();
                    _lastOffboardActions.TryGetValue(deviceId, out var lastOffboardAction);

                    devices.Add(new Device
                    {
                        Id = deviceId,
                        Name = computerDnsName,
                        LastSeen = item["lastSeen"]?.ToString(), // Assuming you have this property
                        LastOffboardAction = lastOffboardAction ?? "Never"
                    });
                }
            }

            return devices;
        }
        private async Task<Dictionary<string, string>> FetchMachineActionsAsync(string appToken)
        {
            var httpClient = HttpClientSingleton.Instance;
            string requestUri = $"https://api.securitycenter.microsoft.com/api/machineactions";

            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", appToken);

            var response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var jsonResponse = JObject.Parse(responseContent);

            var lastOffboardActions = new Dictionary<string, string>();
            foreach (var action in jsonResponse["value"])
            {
                if (action["type"].ToString() == "Offboard")
                {
                    var deviceId = action["machineId"].ToString();
                    var actionDate = action["creationDateTimeUtc"].ToString();
                    if (!lastOffboardActions.ContainsKey(deviceId) || DateTime.Parse(actionDate) > DateTime.Parse(lastOffboardActions[deviceId]))
                    {
                        lastOffboardActions[deviceId] = actionDate;
                    }
                }
            }

            return lastOffboardActions;
        }
        private async Task OffboardDeviceAsync(string deviceId, string comment, string appToken)
        {
            var httpClient = HttpClientSingleton.Instance;
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", appToken);
            var body = new { Comment = comment };
            var content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, "application/json");

            Debug.WriteLine($"https://api.securitycenter.microsoft.com/api/machines/{deviceId}/offboard");

            var response = await httpClient.PostAsync($"https://api.securitycenter.microsoft.com/api/machines/{deviceId}/offboard", content);
            response.EnsureSuccessStatusCode();
        }
        private string DecodeToken(string token)
        {
            var tokenPayload = token.Split('.')[1]
                                    .Replace('-', '+')
                                    .Replace('_', '/');
            while (tokenPayload.Length % 4 != 0)
            {
                tokenPayload += "=";
            }
            var tokenByteArray = Convert.FromBase64String(tokenPayload);
            var tokenArray = Encoding.ASCII.GetString(tokenByteArray);
            var tokObj = JsonConvert.DeserializeObject<JObject>(tokenArray);
            return tokObj["upn"]?.ToString();
        }
        private T FindAncestor<T>(DependencyObject current) where T : DependencyObject
        {
            while (current != null)
            {
                if (current is T)
                {
                    return (T)current;
                }
                current = VisualTreeHelper.GetParent(current);
            }
            return null;
        }
        private void Sort(string sortBy, ListSortDirection direction)
        {
            ICollectionView dataView = CollectionViewSource.GetDefaultView(DeviceListBox.ItemsSource);
            if (dataView == null)
            {
                Debug.WriteLine("dataView is null"); // Debug statement
                return;
            }

            Debug.WriteLine($"Applying sort description: {sortBy} {direction}"); // Debug statement

            dataView.SortDescriptions.Clear();
            SortDescription sd = new SortDescription(sortBy, direction);
            dataView.SortDescriptions.Add(sd);
            dataView.Refresh();
        }
        //UI Functions
        private void DeviceListBox_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            Debug.WriteLine("PreviewMouseLeftButtonDown event fired"); // Debug statement

            var headerClicked = FindAncestor<GridViewColumnHeader>(e.OriginalSource as DependencyObject);
            if (headerClicked != null)
            {
                Debug.WriteLine($"Header clicked: {headerClicked.Content}"); // Debug statement

                if (headerClicked.Role != GridViewColumnHeaderRole.Padding)
                {
                    ListSortDirection direction;

                    if (headerClicked != _lastHeaderClicked)
                    {
                        direction = ListSortDirection.Ascending;
                    }
                    else
                    {
                        direction = _lastDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending;
                    }

                    var sortBy = headerClicked.Column.Header as string;
                    if (!string.IsNullOrEmpty(sortBy))
                    {
                        Debug.WriteLine($"Sorting by {sortBy} in {direction} order"); // Debug statement
                        Sort(sortBy, direction);
                        _lastHeaderClicked = headerClicked;
                        _lastDirection = direction;
                    }
                }
            }
            else
            {
                Debug.WriteLine("Not a GridViewColumnHeader"); // Debug statement
            }
        }
        private async void ActionButton_Click(object sender, RoutedEventArgs e)
        {
            if (ActionButton.Content.ToString() == "Sign In")
            {
                StatusTextBlock.Text = "Signing in, please wait...";

                try
                {
                    // Run sign-in and data retrieval on a separate thread
                    var customers = await Task.Run(async () =>
                    {
                        var credential = new InteractiveBrowserCredential();
                        var scopes = new[] { "https://graph.microsoft.com/.default" };
                        var tokenRequestContext = new TokenRequestContext(scopes);
                        var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));
                        var tokenResponse = await credential.GetTokenAsync(tokenRequestContext, cancellationTokenSource.Token);

                        signedInUsername = DecodeToken(tokenResponse.Token);

                        appSecret = await RetrieveSecretFromKeyVaultAsync("79d5aeee-e34d-434c-9c4c-a25f18f844b9-MortgageWorkSpace-Secret", credential);
                        appRefreshToken = await RetrieveSecretFromKeyVaultAsync("mwsportal-abtcsp-onmicrosoft-com-mortgageworkspace", credential);

                        var cspToken = await GetCspTokenAsync(appRefreshToken, appSecret);
                        return await GetCspCustomersAsync(cspToken);
                    });

                    // Update the UI on the UI thread
                    Dispatcher.Invoke(() =>
                    {
                        allCustomers = customers.OrderBy(c => c.Name).ToList();
                        SelectionBox.ItemsSource = allCustomers;
                        SelectionBox.IsEnabled = true;
                        CustomerSearchBox.IsEnabled = true;
                        SelectionTextBlock.IsEnabled = true;
                        DeviceListBox.IsEnabled = true;
                        DeviceSearchBox.IsEnabled = true;
                        PromptTextBlock.Text = "Please Select a customer"; // Updated text
                        StatusTextBlock.Text = $"Signed in successfully as {signedInUsername}.";
                        ActionButton.Content = "OffBoard";
                    });
                }
                catch (Exception ex)
                {
                    // Output the error message to the debug output
                    Debug.WriteLine($"Error during sign in: {ex}");

                    // Show the error message in a MessageBox
                    Dispatcher.Invoke(() =>
                    {
                        StatusTextBlock.Text = $"Error during sign in: {ex.Message}";
                        MessageBox.Show($"An error occurred: {ex}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
            else if (ActionButton.Content.ToString() == "OffBoard")
            {
                Dispatcher.Invoke(() =>
                {
                    ActionButton.IsEnabled = false;
                });
                if (DeviceListBox.SelectedItem is Device selectedDevice)
                {
                    StatusTextBlock.Text = "Offboarding device...";
                    string comment = $"DeviceOffBoarded by {signedInUsername} at {DateTime.Now:yyyyMMdd}";

                    try
                    {
                        // Run offboarding on a separate thread
                        await Task.Run(async () =>
                        {
                            var appToken = await GetAppTokenAsync(appClientId, appSecret, selectedCustomerId, "https://securitycenter.onmicrosoft.com/windowsatpservice/.default");
                            await OffboardDeviceAsync(selectedDevice.Id, comment, appToken);

                            //Wait for offboarding before refreshing
                            Thread.Sleep(5000);

                            // Fetch updated device list
                            _lastOffboardActions = await FetchMachineActionsAsync(appToken);
                            var devices = await GetDevicesAsync(selectedCustomerId, appToken);

                            // Update the UI on the UI thread
                            Dispatcher.Invoke(() =>
                            {
                                allDevices = devices.OrderBy(d => d.Name).ToList();
                                DeviceListBox.ItemsSource = allDevices;
                                StatusTextBlock.Text = $"Successfully offboarded {selectedDevice.Name}";
                                ActionButton.IsEnabled = true;
                            });
                        });
                    }
                    catch (Exception ex)
                    {
                        // Output the error message to the debug output
                        Debug.WriteLine($"Error during offboarding: {ex}");

                        // Show the error message in a MessageBox
                        Dispatcher.Invoke(() =>
                        {
                            StatusTextBlock.Text = $"Error during offboarding: {ex.Message}";
                            ActionButton.IsEnabled = true;
                            MessageBox.Show($"An error occurred: {ex}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        });
                    }
                }
                else
                {
                    Dispatcher.Invoke(() =>
                    {
                        ActionButton.IsEnabled = true;
                    });
                    StatusTextBlock.Text = "Please select a device to offboard.";
                }
            }
        }

        private async void SelectionBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (SelectionBox.SelectedItem is Customer selectedCustomer)
            {
                selectedCustomerId = selectedCustomer.Id; // Store the selected customer's ID
                StatusTextBlock.Text = "Retrieving devices, please wait...";
                try
                {
                    // Fetch the app token for the selected customer
                    var appToken = await Task.Run(async () =>
                    {
                        return await GetAppTokenAsync(appClientId, appSecret, selectedCustomer.Id, "https://securitycenter.onmicrosoft.com/windowsatpservice/.default");
                    });

                    // Fetch machine actions once and store in a dictionary
                    _lastOffboardActions = await FetchMachineActionsAsync(appToken);

                    // Fetch devices and include the last offboard action
                    var devices = await Task.Run(async () =>
                    {
                        return await GetDevicesAsync(selectedCustomer.Id, appToken);
                    });

                    // Update the UI on the UI thread
                    Dispatcher.Invoke(() =>
                    {
                        allDevices = devices.OrderBy(d => d.Name).ToList();
                        DeviceListBox.ItemsSource = allDevices;
                        DeviceListBox.Visibility = Visibility.Visible;
                        DeviceSearchBox.Visibility = Visibility.Visible;
                        StatusTextBlock.Text = "Devices retrieved successfully.";
                    });
                }
                catch (Exception ex)
                {
                    // Output the error message to the debug output
                    Debug.WriteLine($"Error retrieving devices: {ex}");

                    // Show the error message in a MessageBox
                    Dispatcher.Invoke(() =>
                    {
                        StatusTextBlock.Text = $"Error retrieving devices: {ex.Message}";
                        MessageBox.Show($"An error occurred: {ex}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
        }
        private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed)
                this.DragMove();
        }
        private void ExitImage_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            Application.Current.Shutdown();
        }
        private void CustomerSearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (allCustomers != null)
            {
                var filteredCustomers = allCustomers.Where(c => c.Name.Contains(CustomerSearchBox.Text, StringComparison.OrdinalIgnoreCase)).OrderBy(c => c.Name).ToList();
                SelectionBox.ItemsSource = filteredCustomers;
            }
        }
        private void DeviceSearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (allDevices != null)
            {
                var filteredDevices = allDevices.Where(d => d.Name.Contains(DeviceSearchBox.Text, StringComparison.OrdinalIgnoreCase)).OrderBy(d => d.Name).ToList();
                DeviceListBox.ItemsSource = filteredDevices;
            }
        }
    }
}
