<?php include "functions.php"; ?>
<!DOCTYPE html>
<html lang="en">

<?php
//generate CSRF Token
session_start();
$_SESSION["token"] = bin2hex(random_bytes(32));


?>

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <?= style_script() ?>
    <title>Login</title>
</head>

<body class="text-center">

    <form class="form-signin" method="POST" action="proseslogin.php">
        <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
        <label for="inputUsername" class="sr-only">Username</label>
        <input type="username" id="inputUsername" name="username" class="form-control" placeholder="Username" required autofocus>
        <br>
        <label for="inputPassword" class="sr-only">Password</label>
        <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required>
        <input type="hidden" name="token" value="<?= $_SESSION["token"] ?>" />
        <div class="checkbox mb-3">

        </div>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
        <p class="mt-5 mb-3 text-muted">hk &copy; 2021</p>
    </form>
</body>

</html>