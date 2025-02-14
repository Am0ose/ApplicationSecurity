document.addEventListener("DOMContentLoaded", function () {
    document.querySelector("form").addEventListener("submit", function (event) {
        if (!validateInput()) {
            event.preventDefault(); // Prevent form submission if validation fails
        }
    });
});

function validateInput() {
    var email = document.getElementById("email").value;
    var password = document.getElementById("password").value;
    var confirmPassword = document.getElementById("confirmPassword").value;
    var emailHelp = document.getElementById("emailHelp");
    var passwordHelp = document.getElementById("passwordHelp");
    var confirmPasswordHelp = document.getElementById("confirmPasswordHelp");

    var emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    var passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;

    // Validate Email
    if (!emailRegex.test(email)) {
        emailHelp.innerHTML = "Invalid email format!";
        emailHelp.style.color = "red";
        return false;
    } else {
        emailHelp.innerHTML = "";
    }

    // Validate Password
    if (!passwordRegex.test(password)) {
        passwordHelp.innerHTML = "Password must be at least 12 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.";
        passwordHelp.style.color = "red";
        return false;
    } else {
        passwordHelp.innerHTML = "";
    }

    // Confirm Password Match
    if (password !== confirmPassword) {
        confirmPasswordHelp.innerHTML = "Passwords do not match!";
        confirmPasswordHelp.style.color = "red";
        return false;
    } else {
        confirmPasswordHelp.innerHTML = "";
    }

    return true;
}
