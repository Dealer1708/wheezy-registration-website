
const fileInput = document.getElementById("files")
const runBtn = document.getElementById("run")
fileInput.addEventListener("change", function(){
  runBtn.removeAttribute("disabled")
  runBtn.setAttribute("enabled","")
})

function RunScript(){
  if (document.getElementById("files").files["length"] == 1){
    window.location = "errors"
  }
}
document.getElementById('files').addEventListener("change", handleFileSelect, false);
function handleFileSelect(evt) {

  var files = evt.target.files;
  for (var i = 0, f; f = files[i]; i++) {
    var json = null;
    var reader = new FileReader();
    reader.readAsText(f, "UTF-8");
    reader.onload = function (evt) {
      let file = new FormData();
      file.append("file", evt.target.result);
      fetch("run/script", {
        method: "post",
        body: file
      });
    };
  }
}
