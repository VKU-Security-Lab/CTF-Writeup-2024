<?php
$key = "123";
$salt = "^*@&24";
echo (int)($salt.$key);
srand((int)($salt.$key));