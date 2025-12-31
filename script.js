let shop=document.getElementById("btn-shopnow");
let container=document.getElementById("hf-continer");
let buySell =document.getElementById("hiddenclass");
buySell.classList.add("hiddenclass");
shop.addEventListener("click",function(){
  container.classList.add("hiddenclass");
  buySell.classList.remove("hiddenclass");
});
