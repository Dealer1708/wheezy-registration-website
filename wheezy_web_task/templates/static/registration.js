function sumbitRegForm(){
    let formData=new FormData(sign_up_form);
    fetch("signup/user",
        {
            body: formData,
            method: "post"
        }).then((data) => {return data.json()}).then((data) => {
            if(data["status"] !== "ok"){
                let field = document.getElementById(data["field"])
                field.setCustomValidity(data["message"])
                field.reportValidity()
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
            if (data["status"] === "Fail"){
                document.getElementById("error-text")
                .innerHTML = "Incorrect login or password Try again";
            }
            else{
                window.location = "/home"
            }
        })
}

