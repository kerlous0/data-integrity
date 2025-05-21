// Enable Bootstrap tooltips
document.addEventListener("DOMContentLoaded", function () {
  var tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  // Auto-hide alerts after 5 seconds
  var alerts = document.querySelectorAll(".alert:not(.alert-permanent)");
  alerts.forEach(function (alert) {
    setTimeout(function () {
      var bsAlert = new bootstrap.Alert(alert);
      bsAlert.close();
    }, 5000);
  });

  // File upload validation
  var fileInput = document.getElementById("file");
  if (fileInput) {
    fileInput.addEventListener("change", function (e) {
      var file = e.target.files[0];
      if (file) {
        // Check file size (16MB limit)
        if (file.size > 16 * 1024 * 1024) {
          alert("File size exceeds 16MB limit");
          e.target.value = "";
          return;
        }

        // Check file type
        var allowedTypes = [".pdf", ".docx", ".txt"];
        var ext = "." + file.name.split(".").pop().toLowerCase();
        if (!allowedTypes.includes(ext)) {
          alert(
            "Invalid file type. Please upload PDF, DOCX, or TXT files only."
          );
          e.target.value = "";
          return;
        }
      }
    });
  }

  // Password strength meter
  var passwordInput = document.getElementById("password");
  if (passwordInput) {
    passwordInput.addEventListener("input", function (e) {
      var password = e.target.value;
      var strength = 0;

      if (password.length >= 8) strength++;
      if (/[A-Z]/.test(password)) strength++;
      if (/[a-z]/.test(password)) strength++;
      if (/[0-9]/.test(password)) strength++;
      if (/[^A-Za-z0-9]/.test(password)) strength++;

      var strengthMeter = document.getElementById("password-strength");
      if (strengthMeter) {
        strengthMeter.className = "progress-bar";
        switch (strength) {
          case 0:
          case 1:
            strengthMeter.style.width = "20%";
            strengthMeter.classList.add("bg-danger");
            break;
          case 2:
          case 3:
            strengthMeter.style.width = "60%";
            strengthMeter.classList.add("bg-warning");
            break;
          case 4:
          case 5:
            strengthMeter.style.width = "100%";
            strengthMeter.classList.add("bg-success");
            break;
        }
      }
    });
  }

  // Confirm delete actions
  var deleteButtons = document.querySelectorAll("[data-confirm]");
  deleteButtons.forEach(function (button) {
    button.addEventListener("click", function (e) {
      if (!confirm(this.getAttribute("data-confirm"))) {
        e.preventDefault();
      }
    });
  });
});
