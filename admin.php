
<?php
// admin.php - User and Config Management Panel

// Include necessary functions
include 'user_management_functions.php';

// Define the path for user configurations
$userConfigFile = 'user_configs.json';

// Initialize user configs if the file doesn't exist
if (!file_exists($userConfigFile)) {
    file_put_contents($userConfigFile, json_encode([]));
}

// Handle form submission for updating expiration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['set_expiry'])) {
    $userId = $_POST['user_id'];
    $expiryDate = $_POST['expiry_date'];

    $users = json_decode(file_get_contents($userConfigFile), true);

    // Find the user and update the expiry
    foreach ($users as &$user) {
        if ($user['id'] === $userId) {
            $user['expiry'] = $expiryDate;
            break;
        }
    }

    file_put_contents($userConfigFile, json_encode($users, JSON_PRETTY_PRINT));
    
    // Redirect to avoid form resubmission
    header("Location: admin.php");
    exit;
}

// Dummy function to add a new user (for demonstration)
function addNewUser($configFile, $name, $config) {
    $users = json_decode(file_get_contents($configFile), true);
    $newId = empty($users) ? "user_1" : "user_" . (count($users) + 1);
    
    $users[] = [
        'id' => $newId,
        'name' => $name,
        'config' => $config,
        'expiry' => 'never'
    ];
    
    file_put_contents($configFile, json_encode($users, JSON_PRETTY_PRINT));
}

// Check if we need to add dummy data
$users = json_decode(file_get_contents($userConfigFile), true);
if (empty($users)) {
    addNewUser($userConfigFile, 'Sample User 1', 'vless://...');
    addNewUser($userConfigFile, 'Sample User 2', 'trojan://...');
}
$users = json_decode(file_get_contents($userConfigFile), true);


?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پنل مدیریت کاربران</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            direction: rtl;
            background-color: #f8f9fa;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 20px auto;
            background: #fff;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        h1 {
            color: #0056b3;
            text-align: center;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: right;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: white;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            background-color: #007bff;
            color: white;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .btn:hover {
            background-color: #0056b3;
        }
        .btn-danger {
            background-color: #dc3545;
        }
        .btn-danger:hover {
            background-color: #c82333;
        }
        .modal {
            display: none; 
            position: fixed; 
            z-index: 1; 
            left: 0;
            top: 0;
            width: 100%; 
            height: 100%; 
            overflow: auto; 
            background-color: rgba(0,0,0,0.5);
        }
        .modal-content {
            background-color: #fefefe;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 500px;
            border-radius: 8px;
            text-align: center;
        }
        .close {
            color: #aaa;
            float: left;
            font-size: 28px;
            font-weight: bold;
        }
        .close:hover,
        .close:focus {
            color: black;
            text-decoration: none;
            cursor: pointer;
        }
        input[type="datetime-local"] {
            width: 95%;
            padding: 10px;
            margin-top: 10px;
            border-radius: 5px;
            border: 1px solid #ccc;
        }
    </style>
</head>
<body>

    <div class="container">
        <h1>پنل هوشمند مدیریت انقضای کانفیگ‌ها</h1>
        <table>
            <thead>
                <tr>
                    <th>شناسه کاربر</th>
                    <th>نام کاربر</th>
                    <th>تاریخ انقضا</th>
                    <th>عملیات</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                <tr>
                    <td><?php echo htmlspecialchars($user['id']); ?></td>
                    <td><?php echo htmlspecialchars($user['name']); ?></td>
                    <td><?php echo htmlspecialchars($user['expiry'] == 'never' ? 'نامحدود' : $user['expiry']); ?></td>
                    <td>
                        <button class="btn" onclick="openExpiryModal('<?php echo $user['id']; ?>', '<?php echo $user['expiry']; ?>')">تنظیم/تغییر انقضا</button>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- The Modal -->
    <div id="expiryModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h2>تنظیم تاریخ انقضا</h2>
            <form action="admin.php" method="post">
                <input type="hidden" name="user_id" id="modalUserId">
                <input type="datetime-local" name="expiry_date" id="modalExpiryDate" required>
                <br><br>
                <button type="submit" name="set_expiry" class="btn">ذخیره</button>
                <button type="button" class="btn btn-danger" onclick="setNeverExpiry()">نامحدود</button>
            </form>
        </div>
    </div>

    <script>
        var modal = document.getElementById("expiryModal");
        var modalUserId = document.getElementById("modalUserId");
        var modalExpiryDate = document.getElementById("modalExpiryDate");

        function openExpiryModal(userId, currentExpiry) {
            modalUserId.value = userId;
            // Format for datetime-local input
            if (currentExpiry && currentExpiry !== 'never') {
                 modalExpiryDate.value = currentExpiry;
            } else {
                 modalExpiryDate.value = '';
            }
            modal.style.display = "block";
        }

        function closeModal() {
            modal.style.display = "none";
        }
        
        function setNeverExpiry() {
            // A bit of a trick: we can't submit 'never', so we submit a very far future date
            // Or handle it on the server side. Let's send a special value.
            modalExpiryDate.value = ''; // Clear it
            // Or we can add a new form field
            // For now, let's just close and let user know it needs manual handling or a dedicated button.
            // A better implementation would be a separate button on the form.
            // Let's make this button submit the form with a special value
             var form = modalExpiryDate.form;
             var input = document.createElement('input');
             input.type = 'hidden';
             input.name = 'expiry_date';
             input.value = 'never';
             form.appendChild(input);
             form.submit();
        }

        window.onclick = function(event) {
            if (event.target == modal) {
                closeModal();
            }
        }
    </script>

</body>
</html>
