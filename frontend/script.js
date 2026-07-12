function register() {
  console.log("BUTTON CLICKED 🔥");

  const name = document.getElementById("name").value;
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  fetch("http://localhost:3000/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ name, email, password })
  })
    .then(res => res.text())
    .then(data => {
      console.log(data);
      alert(data);
    })
    .catch(err => console.error("FETCH ERROR:", err));
}