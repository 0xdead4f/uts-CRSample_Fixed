<?php
include 'functions.php';
session_start();
//check validate token
if (!isset($_POST["token"]) || !isset($_SESSION["token"])) {
    exit("token not set!");
}
if ($_POST["token"] == $_SESSION["token"]) {
    unset($_SESSION["token"]);

    $notif = null;
    if (isset($_POST['username']) && isset($_POST['password'])) {


        //melakukan sanitasi html special character
        $user = htmlspecialchars($_POST['username']);
        $pass = htmlspecialchars($_POST['password']);
        //melakukan validasi inputan
        if ($user == "") {
            echo "<script>window.location.href = 'login.php';alert('Username harus diisi!');</script>";
        } elseif ($pass == "") {
            echo "<script>window.location.href = 'login.php';alert('Password harus diisi!');</script>";
        }
        // $salt = "XDrBmrW9g2fb";
        // mengambil salt dengan aman
        $pdo_salt = pdo_connect();
        $stmt_salt = $pdo_salt->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
        $stmt_salt->bindParam(1, $user);
        $stmt_salt->execute();
        $salt = $stmt_salt->fetch(PDO::FETCH_ASSOC);
        $pdo = pdo_connect();
        $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ? LIMIT 1');
        //menggunakan bind param PDO
        $stmt->bindParam(1, $user);
        $stmt->bindParam(2, hash('sha256', $pass . $salt['salt']));
        $stmt->execute();
        $notif = $stmt->rowCount();
        if ($stmt->rowCount() > 0) {
            $_SESSION['user'] = $user;
            header("location: index.php");
        } else {
            echo "<script>window.location.href = 'login.php';alert('Password/Username Salah!');</script>";
        }
    }
} else {
    exit("invalid token!");
}