exports.totp = () => `
<html>
    <body>
    <center>
        <h2>Verify your identity with the code in your ACME app:</h2>
        <form method="post" action="/">
            <div>
                Username
                <input name="username" type="text">
                Password
                <input name="password" type="password">
            </div>
            <div>
                <p>ACME Code</p>
                <input name="totp" type="text">
            </div>
            <div>
                <input type="submit" value="Submit">
            </div>
        </form>
    </center>
    </body>
</html>
`;

exports.login = (id) => `
<html>
    <body>
    <center>
        <h2>Welcome, ${id}! Insert your password:</h2>
        <form method="post" action="/">
            <input name="username" value="${id}" type="hidden">
            <div>
                <input name="password" type="password">
                <input type="submit" value="Submit">
            </div>
        </form>
    </center>
    </body>
</html>
`;


