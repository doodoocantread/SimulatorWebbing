(function () {
  function show(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  var login = document.getElementById("login-form");
  if (login) {
    login.addEventListener("submit", function (event) {
      event.preventDefault();
      var data = Object.fromEntries(new FormData(login));
      fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      })
        .then(function (res) { return res.json().then(function (body) { return [res.ok, body]; }); })
        .then(function (result) {
          if (result[0]) {
            sessionStorage.setItem("token", result[1].token);
            show("login-status", "Signed in as " + result[1].user.username);
          } else {
            show("login-status", result[1].error || "Sign in failed");
          }
        });
    });
  }

  var comment = document.getElementById("comment-form");
  if (comment) {
    comment.addEventListener("submit", function (event) {
      event.preventDefault();
      var token = sessionStorage.getItem("token");
      if (!token) { show("comment-status", "Sign in first"); return; }
      fetch(comment.dataset.api + "/comments", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
        body: JSON.stringify({
          product_id: Number(comment.dataset.product),
          body: comment.elements.body.value,
        }),
      }).then(function (res) {
        if (res.ok) { window.location.reload(); } else { show("comment-status", "Could not post comment"); }
      });
    });
  }
})();
