let shop=document.getElementById("btn-shopnow");
let container=document.getElementById("hf-continer");
let buySell =document.getElementById("hiddenclass");
let attcbtn=document.getElementById("attc-btn");
buySell.classList.add("hiddenclass");
shop.addEventListener("click",function(){
  container.classList.add("hiddenclass");
  buySell.classList.remove("hiddenclass");

});
 attcbtn.addEventListener("click",function(){
  buySell.classList.add("hiddenclass");
  container.classList.remove("hiddenclass");  });