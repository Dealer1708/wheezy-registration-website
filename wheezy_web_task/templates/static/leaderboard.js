
fetch("leaderboard/user", {method: "post"})
    .then(data => {return data.json()})
    .then(data => {
        const body = data["body"]
        let markup = ``
        console.log(body)
        for (let i = 0; i < body.length; i++){
            markup = `<tr><td>${body[i][0]}</td><td>${body[i][1]}</td>`
            document.querySelector("#score-table").insertAdjacentHTML('beforeend',markup)
            console.log(data["body"][i][0])
        }
    })