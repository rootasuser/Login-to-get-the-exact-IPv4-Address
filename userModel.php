<?php

class UserModel
{
    private $db;

    public function __construct($db)
    {
        $this->db = $db;
    }

    public function validateLogin($username, $password, $role)
    {
        $username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        $role = filter_var($role, FILTER_SANITIZE_SPECIAL_CHARS);

        // Validate role
        $allowedRoles = RoleModel::getRoles();
        if (!in_array($role, $allowedRoles)) {
            $this->logFailedLogin($username, 'Invalid role');
            return false;
        }

        $sql = "SELECT id, username, password, role, firstname, lastname, middlename, profile, position, status 
                FROM users 
                WHERE username = :username AND role = :role";
        
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->bindParam(':role', $role, PDO::PARAM_STR);
            $stmt->execute();

            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                if ($user['status'] === 'disabled') {
                    $this->logFailedLogin($username, 'Account is disabled');
                    return false;
                }

                if (password_verify($password, $user['password'])) {
                    unset($user['password']);

                    $ipAddress = $this->getRealIp(); // Get correct IPv4 Address

                    date_default_timezone_set('Asia/Manila');
                    $datetime = date('Y-m-d H:i:s');
                    $action = htmlspecialchars("$username successfully logged in at $datetime", ENT_QUOTES, 'UTF-8');

                    $this->logHistory($username, $action, $datetime, $ipAddress);

                    return $user;
                } else {
                    $this->logFailedLogin($username, 'Invalid credentials');
                }
            } else {
                $this->logFailedLogin($username, 'Invalid credentials');
            }
        } catch (PDOException $e) {
            error_log($e->getMessage());
            $this->logFailedLogin($username, 'Database error');
            return false;
        }

        return false;
    }

    private function logHistory($username, $action, $datetime, $ipAddress)
    {
        $historySql = "INSERT INTO admins_history_tbl (username, action, datetime, ip_address) 
                       VALUES (:username, :action, :datetime, :ip_address)";
        $historyStmt = $this->db->prepare($historySql);
        $historyStmt->bindParam(':username', $username, PDO::PARAM_STR);
        $historyStmt->bindParam(':action', $action, PDO::PARAM_STR);
        $historyStmt->bindParam(':datetime', $datetime, PDO::PARAM_STR);
        $historyStmt->bindParam(':ip_address', $ipAddress, PDO::PARAM_STR);
        $historyStmt->execute();
    }

    private function logFailedLogin($username, $reason)
    {
        $ipAddress = $this->getRealIp();
        date_default_timezone_set('Asia/Manila');
        $datetime = date('Y-m-d H:i:s');
        $action = htmlspecialchars("Failed login attempt for username: '$username' - Reason: $reason", ENT_QUOTES, 'UTF-8');

        $historySql = "INSERT INTO admins_history_tbl (username, action, datetime, ip_address) 
                       VALUES (:username, :action, :datetime, :ip_address)";
        $historyStmt = $this->db->prepare($historySql);
        $historyStmt->bindValue(':username', $username ?: null, PDO::PARAM_STR);
        $historyStmt->bindParam(':action', $action, PDO::PARAM_STR);
        $historyStmt->bindParam(':datetime', $datetime, PDO::PARAM_STR);
        $historyStmt->bindParam(':ip_address', $ipAddress, PDO::PARAM_STR);
        $historyStmt->execute();
    }

    private function getRealIp()
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        } else {
            $ip = 'UNKNOWN';
        }

        // Convert "::1" (IPv6 localhost) or "127.0.0.1" to actual LAN IPv4
        if ($ip === '::1' || $ip === '127.0.0.1') {
            $ip = $this->getLanIp();
        }

        return $ip;
    }

    private function getLanIp()
    {
        $ip = '127.0.0.1';

        if (PHP_OS_FAMILY === 'Windows') {
            $output = shell_exec('ipconfig');
            if (preg_match_all('/IPv4 Address[.\s]+: ([\d.]+)/', $output, $matches)) {
                foreach ($matches[1] as $lanIp) {
                    if (!preg_match('/^169\.254\./', $lanIp)) { // Ignore APIPA addresses
                        $ip = $lanIp;
                        break;
                    }
                }
            }
        } else {
            $output = shell_exec("ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}'");
            $ips = explode("\n", trim($output));
            foreach ($ips as $lanIp) {
                if (!empty($lanIp) && $lanIp !== '127.0.0.1') {
                    $ip = $lanIp;
                    break;
                }
            }
        }

        return $ip;
    }
}

?>
