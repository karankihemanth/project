const handleRegisterSubmit = async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const data = Object.fromEntries(formData);

  const response = await fetch('http://localhost:5000/register', {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json',
    }
  });

  const result = await response.text();
  if (result.includes('User registered...')) {
    window.location.href = '/dashboard';
  } else {
    alert(result);
  }
};


const handleLoginSubmit = async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);

  const response = await fetch('http://localhost:5000/login', {
    method: 'POST',
    body: new URLSearchParams(formData),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    }
  });

  const data = await response.json();
  if (data.message === 'Login successful') {
    localStorage.setItem('token', data.token);
    window.location.href = '/dashboard';
  } else {
    alert(data);
    alert("Login failed, please try again.");
  }
};
