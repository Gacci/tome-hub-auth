import crypto from 'crypto';
import { diskStorage } from 'multer';
import { extname } from 'path';

export const userProfileStorage = diskStorage({
  destination: './public/profiles', // Directory to store the files
  filename: (req, file, callback) => {
    callback(
      null,
      `${(Date.now().toString() + crypto.randomBytes(16).toString('hex')).slice(0, 32).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5')}${extname(file.originalname)}`
    );
  }
});
