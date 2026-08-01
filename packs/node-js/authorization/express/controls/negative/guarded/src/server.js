import express from 'express';
import userRoutes from './routes/user.js';
import theoryRoutes from './routes/theory.js';
const app = express();
app.use('/api/users', userRoutes);
app.use('/api/theory', theoryRoutes);
