let shop=document.getElementById("btn-shopnow");
let header=document.querySelector("header");
shop.addEventListener("click",function(){
  header.classList.toggle("hiddenclass");
});