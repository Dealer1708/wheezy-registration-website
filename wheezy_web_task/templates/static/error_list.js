
const fixedCheckBox = document.getElementById("fixed")
const nonFixedCheckBox = document.getElementById("non-fixed")
const selectItemsPerPage = document.getElementById("items-on-page")
let itemsPerPage = 5;
let count = 0

selectItemsPerPage.addEventListener("change", function(){
  itemsPerPage = selectItemsPerPage.value
  Run()
})


fixedCheckBox.addEventListener("change", function(){
  if(fixedCheckBox.checked){
    fixedCheckBox.checked = true
  }
  else if(!fixedCheckBox.checked){
    fixedCheckBox.checked = false
  }
  Run()
})
nonFixedCheckBox.addEventListener("change", function(){
  if(nonFixedCheckBox.checked){
    nonFixedCheckBox.checked = true
  }
  else if(!nonFixedCheckBox.checked){
    nonFixedCheckBox.checked = false
  }
  Run()
})

document.getElementById("filters").addEventListener("click", function(){
  if(count == 0){
    const items = document.getElementById("filter-nav")
    items.style.display = "flex"
    items.style.zIndex = 0
    count = 1
    return
  }
  if (count == 1){
    const items = document.getElementById("filter-nav")
    items.style.zIndex = -1
    items.style.display = "none"
    count = 0
    return
  }
})

function Run(){
  fetch("get/error", {method: "post"})
  .then(data => {return data.json()})
  .then(data => {
    const listItems = data["errors"]
    const paginationNumbers = document.getElementById("pagination-numbers");
    const prevButton = document.getElementById("prev-button");
    const listContainer = document.getElementById("list-container");
    const nextButton = document.getElementById("next-button");
    let filteredItems = []
    let currentPage = 1;


  if (fixedCheckBox.checked && !nonFixedCheckBox.checked) {
    for (let i = 0; i < listItems.length; i++){
      if(listItems[i][1] == "1"){
        filteredItems.push(listItems[i])
      }
    }
  }
  else if (!fixedCheckBox.checked && nonFixedCheckBox.checked)
  {
    for (let i = 0; i < listItems.length; i++){
      if(listItems[i][1] == "0"){
        filteredItems.push(listItems[i])
      }
    }
  } else{
    filteredItems = listItems;
  }

  
  function displayItems() {
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;

  listContainer.innerHTML = '';



  for (let i = startIndex; i < endIndex; i++) {
    if (i < filteredItems.length) {
      const item = document.createElement('td');
      const fixed_item = document.createElement('td');
      const itemTR = document.createElement('tr');
      item.textContent = filteredItems[i][0];
      item.setAttribute("style", "margin-bottom: 10px; text-align: left; width: 100%;")
      if (filteredItems[i][1] == "1"){
        fixed_item.innerHTML += " &#9989;"
      }
      if (filteredItems[i][1] == "0"){
        fixed_item.innerHTML += " &#10060;"
      }
      itemTR.appendChild(item)
      itemTR.appendChild(fixed_item)
      listContainer.appendChild(itemTR)
      
    }
  }
  
  listContainer.scrollTop = 0; 
  }
  
  
  
  function updatePaginationButtons() {
    prevButton.disabled = currentPage === 1;
    nextButton.disabled = currentPage === Math.ceil(filteredItems.length / itemsPerPage);
    document.getElementById(`page${currentPage}`).disabled = true
    for (let i = 0; i < Math.ceil(filteredItems.length / itemsPerPage); i++){
      const pageNumber = document.getElementById(`page${i + 1}`)
      if(currentPage != i + 1){
        pageNumber.disabled = false
      } 
    }
  }
  
  function appendPageNumber(index) {
    const pageNumber = document.createElement("button");
    pageNumber.textContent = index;
    pageNumber.setAttribute("page-index", index);
    pageNumber.setAttribute("class", "pages");
    pageNumber.setAttribute("id", `page${index}`);
    pageNumber.addEventListener("click", () => {
      currentPage = index;
      displayItems();
      updatePaginationButtons();
    });
    paginationNumbers.appendChild(pageNumber);
  }
  
  function createPagination() {
    paginationNumbers.innerHTML = "";
  
    const totalPages = Math.ceil(filteredItems.length / itemsPerPage);
    for (let i = 1; i <= totalPages; i++) {
      appendPageNumber(i);
    }
  
    updatePaginationButtons();
  }
  
  prevButton.addEventListener("click", () => {
    const pageNumber = document.getElementById(`page${currentPage - 1}`)
    if(pageNumber.textContent == currentPage - 1){
      pageNumber.disabled = true
      document.getElementById(`page${currentPage}`).disabled = false
    }
    if (currentPage > 1) {
      currentPage--;
      displayItems();
      updatePaginationButtons();
    }
  });
  
  nextButton.addEventListener("click", () => {
    const totalPages = Math.ceil(filteredItems.length / itemsPerPage);
    if (currentPage < totalPages) {
      currentPage++;
      const pageNumber = document.getElementById(`page${currentPage }`)
      if(pageNumber.textContent == currentPage){
        pageNumber.disabled = true
        document.getElementById(`page${currentPage - 1}`).disabled = false
      }
      displayItems();
      updatePaginationButtons();
    }
  });
  displayItems();
  createPagination();

})  }

Run()







