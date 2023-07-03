function submitRequestForm(){
    let formData = new FormData();
    let anyReqChecked = false
    const rolecheckBox = document.querySelectorAll("input")
    for(let i=0; i<rolecheckBox.length; i++){
        if(rolecheckBox[i].checked){
            formData.append("request",rolecheckBox[i].value)
            anyReqChecked = true
        }
    }
    if(anyReqChecked){
    fetch("submitrequests",
        {
            body: formData,
            method: "post"
        })
    fetch("submitrequests",
    {
        body: formData,
        method: "post"
    }).then((data) => {return data.json()}).then((data) => {
        if (data["status"] == "fail"){
            alert(data["message"])
        }
        else if(data["status"] == "ok"){
            alert(data["message"])
        }
    })
}
}

const dropdown_req = document.getElementById(`dropdown-req`)
const dropdown_req_menu = document.getElementById(`dropdown-menu-req`)

dropdown_req.addEventListener("click",function()
    {
      if(dropdown_req_menu.style.display =="none"){
        dropdown_req_menu.style.display = "block"
      }
      else if(dropdown_req_menu.style.display == "block"){
        dropdown_req_menu.style.display = "none"
      }

      
    })


    document.addEventListener('click', function(event) {
        if (!dropdown_req.contains(event.target)) {
          dropdown_req_menu.style.display = "none"
        }
      })
    
