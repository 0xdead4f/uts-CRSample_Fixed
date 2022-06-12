<?php
$notif = null;
session_start();
include 'functions.php';
if (!isset($_SESSION['user']) || !isset($_SESSION['token'])) {
    header("location: login.php");
}else{
            $pdo = pdo_connect();

            if (isset($_GET['id'])) {
                if (!empty($_POST)) {
                    // sanitasi semua form 
                    $name = $_POST['name'];
                    $name = filter_var($name, FILTER_SANITIZE_STRING);
                    $email = $_POST['email'];
                    $email = filter_var($email, FILTER_SANITIZE_STRING);
                    $phone = $_POST['phone'];
                    $phone = filter_var($phone, FILTER_SANITIZE_STRING);
                    $title = $_POST['title'];
                    $title = filter_var($title, FILTER_SANITIZE_STRING);
                    // Insert new record into the contacts table
                    // $pdo->beginTransaction();
                    if (empty($name) || empty($email) || empty($phone) || empty($title)) {
                            $notif = "Form tidak boleh kosong";
                    }else {
                // Race condition menggunakan semaphore
                if (!function_exists('sem_get')) {
                    function sem_get($key)
                    {
                        return fopen(__FILE__ . '.sem.' . $key, 'w+');
                    }
                    function sem_acquire($sem_id)
                    {
                        return flock($sem_id, LOCK_EX);
                    }
                    function sem_release($sem_id)
                    {
                        return flock($sem_id, LOCK_UN);
                    }
                }
                $sem = sem_get(1234, 1);
                if (sem_acquire($sem)) {


                    $stmt = $pdo->prepare('UPDATE contacts SET name = ?, email = ?, phone = ?, title = ? WHERE id = ?');
                    $stmt->execute([$name, $email, $phone, $title, $_GET['id']]);
                    header("location:index.php");
                     }   
                }
                   

                $stmt = $pdo->prepare('SELECT * FROM contacts WHERE id = ?');
                $stmt->execute([$_GET['id']]);
                $contact = $stmt->fetch(PDO::FETCH_ASSOC);
                if (!$contact) {
                    die('Contact doesn\'t exist!');
                }
            } else {
                die('No ID specified!');
            }
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <?= style_script() ?>
    <title>Change contact</title>
</head>

<body>
    <div class="container" style="margin-top:50px">
        <div class="row">
            <div class="col-md-5 col-sm-12 col-xs-12">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Update contact # <?= $contact['id'] ?></h5>
                        <form action="update.php?id=<?= $contact['id'] ?>" method="post">
                            <input class="form-control form-control-sm" placeholder="Type name" type="text" name="name" value="<?= $contact['name'] ?>" id="name" required><br>
                            <input class="form-control form-control-sm" placeholder="Email" type="text" name="email" value="<?= $contact['email'] ?>" id="email" required><br>
                            <input class="form-control form-control-sm" placeholder="Phone number" type="text" name="phone" value="<?= $contact['phone'] ?>" id="phone"><br>
                            <input class="form-control form-control-sm" placeholder="Title" type="text" name="title" value="<?= $contact['title'] ?>" id="title"><br>
                            <div class="checkbox mb-3">
                                    <label>
                                        <?= $notif ?>
                                    </label>
                                </div>
                            <input class="btn btn-primary btn-sm" type="submit" value="Update">
                            <a href="index.php" type="button" class="btn btn-warning btn-sm">Cancel</a>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-7 col-sm-12 col-xs-12"></div>
        </div>
    </div>

    <div class="text-center">
        <p class="mt-5 mb-3 text-muted">hk &copy; 2021</p>
    </div>
</body>

</html>