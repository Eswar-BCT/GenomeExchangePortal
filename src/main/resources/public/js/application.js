function userLogin() {
  var userName = document.getElementById("userName").value;
  var password = document.getElementById("password").value;
  if (userName !== null && userName !== '' && password !== null && password !== '') {
    var userJSON = '{"userName":"' + userName + '","password":"' + password + '"}';
    url = "http://localhost:9090/login?userName=" + userName + "&password=" + password;
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        var data = this.responseText;
        console.log(data);
        if (data !== null) {
          var obj = JSON.parse(data);
          localStorage.setItem("userName", obj.userName);
          localStorage.setItem("AccessToken", obj.session.accessToken);
          if (obj.newPasswordRequired === true) {
            location.replace("http://localhost:9090/changepassword.html")
          } else {
            location.replace("http://localhost:9090/welcome.html")
          }
        }
      }
    };
    xhttp.open("POST", url, true);
    xhttp.setRequestHeader("Content-type", "application/json");
    xhttp.send(null);
  } else {
    alert("Please enter user name and password..");
  }
}

function loginChangePassword() {

  var userName = localStorage.getItem("userName");
  var password = document.getElementById("old_password").value;
  var conformPassword = document.getElementById("password").value;
  var userJSON = '{"userName":"' + userName + '","oldPassword":"' + password + '","newPassword":"' + conformPassword + '"}';
  url = "http://localhost:9090/loginFirst";
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      alert("Password changed successfully, Loging with new password..");
      location.replace("http://localhost:9090")
    }
  };
  xhttp.open("POST", url, true);
  xhttp.setRequestHeader("Content-type", "application/json");
  xhttp.send(userJSON);
}

function resetPassword() {
  var userName = document.getElementById("user_name").value;
  if (userName !== null && userName !== '') {
    url = "http://localhost:9090/forgotpwd?userName=" + userName;
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        alert(this.responseText);
        location.replace("http://localhost:9090");
      }
    };
    xhttp.open("GET", url);
    xhttp.send();
  } else {
    alert("Please enter user name/email..");
  }
}

function verifyToken() {
  var accessToken = document.getElementById("token").value;
  if (accessToken !== null && accessToken !== '') {
    url = "http://localhost:9090/verifytoken?access_token=" + accessToken;
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        var response = this.responseText;
        if (response !== null) {
          var obj = JSON.parse(response);
          console.log(obj)
          alert("Your Access Token Verified Successfully..\n\nEmail =" + obj.email + ",\nUserName =" + obj.userName);
          innerHTML = obj.email;
        }
      }
    };
    xhttp.open("GET", url);
    xhttp.setRequestHeader("Content-type", "application/json");
    xhttp.send(null);
  } else {
    alert("Please find the access token in Local Storage and enter in text box.. ")
  }
}


function oktaLogin() {
  var AccessToken = localStorage.getItem("AccessToken");
  var domain = "dev-574123.okta.com";
  var clientId = "0oa2387f2xR4pQ6ug357";
  var redirect_uri = "http%3A%2F%2Flocalhost%3A9090%2Foktalogin"
  if (AccessToken !== null || AccessToken !== '') {
    location.replace("https://" + domain + "/oauth2/default/v1/authorize?client_id=" + clientId
      + "&response_type=code&scope=openid&redirect_uri=" + redirect_uri
      + "&state=state-296bc9a0-a2a2-4a57-be1a-d0e2fd9bb601");
  } else {
    alert("access token available..")
  }
}

function verifyOktaToken() {

  var accesstoken = document.cookie.split('=');
  console.log(accesstoken[1]);
  var accesstoken = document.getElementById("okta_token").value;
  if (accesstoken !== null && accesstoken !== '') {
    var url = "http://localhost:9090/token?access_token=" + accesstoken;
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        var response = this.responseText;
        console.log(response)
        if (response !== null) {
          var obj = JSON.parse(response);
          if (obj) {
            alert("Your Access Token Verified Successfully.. \n\nactive:" + obj);
          } else {
            alert("Your Access Token Not valid.. \n\nactive:" + obj);
          }
        }
      }
    };
    xhttp.open("GET", url);
    xhttp.setRequestHeader("Content-type", "application/json");
    xhttp.send(null);
  } else {
    alert("Please find the access token in Cookies and enter in text box.. ")
  }
}

function SignOut() {
  var accessToken = localStorage.getItem("AccessToken");
  var userName = localStorage.getItem("userName");
  var url = "http://localhost:9090/signout?access_token=" + accessToken + "&userName=" + userName;
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      var response = this.responseText;
      console.log(response);
      localStorage.clear();
      location.replace("http://localhost:9090")
    }
  };
  xhttp.open("GET", url);
  xhttp.setRequestHeader("Content-type", "application/json");
  xhttp.send(null);
}

function contentdata() {

  var htmldata = CKEDITOR.instances.Editor.document.getBody().getHtml();
  console.log(htmldata);
  var content = document.getElementById("content").value;
  console.log(content);
}


function submitcontent() {

  var email = document.getElementById("from_email").value;
  var subject = document.getElementById("subject").value;
  var body = data.getData();
  document.getElementById("hide").style.display = 'none';
  document.getElementById("demo").innerHTML = data.getData();
  //window.open('mailto:' + email + '?subject=' + subject + '&body=' + body);
  alert("Email has been sent to Patient to Enroll..")
}



