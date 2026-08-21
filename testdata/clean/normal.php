<?php
function hello($name){
  return "Hello, ".htmlspecialchars($name);
}
add_action("init","hello");
echo hello("world");
