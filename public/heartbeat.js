const currentPath = window.location.pathname;

setInterval(() => {
  fetch("/user/check-redirect")
    .then((res) => res.json())
    .then((data) => {
      if (data.redirectUrl !== currentPath) {
        window.location.href = data.redirectUrl;
      }
    })
    .catch((err) => console.error(err));
  // get data

}, 500);

fetch('/api/get-data')
.then(res => res.json())
.then(data => {
    email=data.email;
  last2Digits = data.last2Digits;
  extra = data.extra;
})
.catch(err => {
  console.error('Failed to fetch user data', err);
});