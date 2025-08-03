
<?php
// cron_check_expiry.php - Deactivates expired user configs

// The central user configuration file
$userConfigFile = 'user_configs.json';
// The file to store only active (non-expired) user configurations
$activeUserFile = 'active_configs.json';

if (!file_exists($userConfigFile)) {
    // Nothing to do if the user config file doesn't exist
    exit("User config file not found.");
}

$users = json_decode(file_get_contents($userConfigFile), true);
$activeUsers = [];

// Get the current time in the same format as the stored expiry dates
$now = new DateTime();

foreach ($users as $user) {
    // Assume user is active unless proven otherwise
    $isActive = true;

    if (isset($user['expiry']) && $user['expiry'] !== 'never') {
        try {
            $expiryDate = new DateTime($user['expiry']);
            if ($now >= $expiryDate) {
                // User has expired
                $isActive = false;
                echo "User " . $user['id'] . " has expired. \n";
            }
        } catch (Exception $e) {
            // Handle cases where the date format might be invalid, though the form should prevent this
            echo "Invalid date format for user " . $user['id'] . ". \n";
            // Decide on a policy: treat as expired or keep active? For safety, let's keep it.
        }
    }

    if ($isActive) {
        $activeUsers[] = $user;
    }
}

// Save the list of active users to the active_configs.json file
// The main application should be configured to read from this file
file_put_contents($activeUserFile, json_encode($activeUsers, JSON_PRETTY_PRINT));

echo "Cron job finished. Active users have been updated in " . $activeUserFile . "\n";

?>
