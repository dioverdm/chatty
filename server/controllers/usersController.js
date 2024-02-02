const User = require("../models/userModel");
const bcrypt = require("bcrypt");

module.exports.register = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    const usernameExists = await User.findOne({ username });
    if (usernameExists)
      return res.json({ msg: "Username is already in use", status: false });

    const emailExists = await User.findOne({ email });
    if (emailExists)
      return res.json({ msg: "Email is already in use", status: false });

    const passwordEnc = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      username,
      password: passwordEnc,
    });
    delete user.password;

    return res.json({ status: true });
  } catch (ex) {
    next(ex);
  }
};

module.exports.login = async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (!user)
            return res.json({ msg: "Incorrect Username or Password", status: false });
      
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid)
            return res.json({ msg: "Incorrect Username or Password", status: false });
      
        delete user.password;
        return res.json({ status: true, user });
    } catch (ex) {
        next(ex);
    }
};
