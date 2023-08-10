// function sumbitRegForm(){
//     fetch("register",
//         {method: "post"})
//         .then((data) => {return data.json()})
//         .then((data) => {
//             if (!data["success"]){
//                 console.log(data)
//                 error = data["errors"]

//                 for(const key of Object.entries(error)){
//                     console.log(key)
//                 }
//             }
//             // if(!data["status"]){
//             //     document.getElementById("error-text")
//             //     .innerHTML = data["message"];
//             // }
//             // else{
//             //     window.location = "/home"
//             // }
//         })
//     }

// function submitLoginForm(){
//     let formData=new FormData(login_form);
//     fetch("login/user",
//         {
//             body: formData,
//             method: "post"
//         }).then((data) => {return data.json()}).then((data) => {
//             if (data["error"]){
//                 document.getElementById("error-text")
//                 .innerHTML = "Incorrect login or password Try again";
//             }
//             else{
//                 window.location = "/home"
//             }
//         })
// }
