
const tableRowLentgh = document.getElementById("score-table").rows.length

for (let i = 0; i < tableRowLentgh - 1; i++){
  if(document.getElementById(`dropdown-req${i}`) != null){
    const dropdown_req = document.getElementById(`dropdown-req${i}`)
    const dropdown_req_menu = document.getElementById(`dropdown-menu-req${i}`)
    const labels = dropdown_req_menu.querySelectorAll(`label`)

    for(let j = 0; j < labels.length; j++){
      const approveBtn = document.getElementById(`approve${labels[j].id}${i}`)
      const denyBtn = document.getElementById(`deny${labels[j].id}${i}`)
      const inputCheckBox = document.getElementById(`${labels[j].id}${i}`)
      approveBtn.addEventListener("click",function(){
        if(!inputCheckBox.checked){
          inputCheckBox.checked = true;
        }
      })
      denyBtn.addEventListener("click",function(){
        if(inputCheckBox.checked){
          inputCheckBox.checked = false
        }
      })
    }

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
  }


  if(document.querySelector(`#dropdown${i}`) != null){
  const dropdown = document.querySelector(`#dropdown${i}`);
  const dropdownMenu = dropdown.querySelector(`#dropdown-menu${i}`)


  document.addEventListener('click', function(event) {
    if (!dropdown.contains(event.target)) {
      dropdownMenu.style.display = "none"
    }
  })
  dropdown.addEventListener("click", function(){
      if(dropdownMenu.style.display == "none"){
        dropdownMenu.style.display = "block"
      }
      else if(dropdownMenu.style.display == "block"){
        dropdownMenu.style.display = "none"
      }
    })
}
}


document.getElementById("submit-btn").addEventListener("click", function(){
    
  let formData = new FormData()
  let formData1 = new FormData()
  let formData1isEmpty = true;
  for (var j = 0; j < tableRowLentgh; j++) {
    const login = document.getElementById(`logins${j}`)
    const dropdown_req_menu = document.getElementById(`dropdown-menu-req${j}`)
    let labels;
    let req = [];
    if (dropdown_req_menu != null){
      labels = dropdown_req_menu.querySelectorAll(`label`)
      for(let i = 0; i < labels.length; i++){
        req.push(labels[i].id)
      }
    }
    if(document.querySelector(`#dropdown${j}`) != null){
      const dropdown = document.querySelector(`#dropdown${j}`);
      const selectedOptions = dropdown.querySelectorAll('input');
      let isAnyOptionSelected = false
      for (let i = 0; i < selectedOptions.length; i++){

        if(selectedOptions[i].checked){
          isAnyOptionSelected = true
          formData.append(login.innerHTML,selectedOptions[i].value)
          if(req.length != 0){
            if(req.includes(selectedOptions[i].value)){
              formData1.append(login.innerHTML,selectedOptions[i].value)
            }
          }
      }
      }
      if (!isAnyOptionSelected){
        formData.append(login.innerHTML, "")
      }

      const formEntries = formData1.entries();
      if (!formEntries.next().done) {
        formData1isEmpty = false;
      }
  }
  }
  
  fetch("post/new/roles",
  {
      body: formData,
      method: "post"
  })
  if(!formData1isEmpty){
    fetch("req/del",
    {
        body: formData1,
        method: "post"
    })}
  location.reload()
})
