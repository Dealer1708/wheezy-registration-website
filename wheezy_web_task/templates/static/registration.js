function sumbitRegForm(){
    let formData=new FormData(sign_up_form);
    fetch("signup/user",
        {
            body: formData,
            method: "post"
        }).then((data) => {return data.json()}).then((data) => {
            if(!data["status"]){
                document.getElementById("error-text")
                .innerHTML = data["message"];
            }
            else{
                window.location = "/home"
            }
        })
}

function submitLoginForm(){
    let formData=new FormData(login_form);
    fetch("login/user",
        {
            body: formData,
            method: "post"
        }).then((data) => {return data.json()}).then((data) => {
            if (data["error"]){
                document.getElementById("error-text")
                .innerHTML = "Incorrect login or password Try again";
            }
            else{
                window.location = "/home"
            }
        })
}
