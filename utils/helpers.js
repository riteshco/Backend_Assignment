import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const hashPswd = async (pswd) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashPswd = await bcrypt.hash(pswd, salt);
        return hashPswd;
    } catch (error) {
        throw new Error('Error hashing password: ' + error.message);
    }
}
export const verifyPswd = async (pswd, hashPswd) => {
    try {
        const isMatch = await bcrypt.compare(pswd, hashPswd);
        return isMatch;
    } catch (error) {
        throw new Error('Error verifying password: ' + error.message);
    }
}
export const generateToken = (response) => {
    try{
        const token = jwt.sign({ username: response.username, email: response.email , user_role: response.user_role } , process.env.JWT_SECRET , {expiresIn: '1h'});
        return token;
    }
    catch (error){
        throw new Error('Error generating token:' + error.message); 
    }
}

export const authenticateToken = (req ,res , next) => {

    // const token = req.headers['authorization']?.split(' ')[1];

    const token = req.cookies.token;

    if (!token) return res.status(401).json({ error: 'Access token is missing' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid access token' });
        }
        req.user = user;
        next();
    });
}