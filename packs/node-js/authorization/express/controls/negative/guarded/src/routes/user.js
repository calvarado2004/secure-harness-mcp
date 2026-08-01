// Correct implementations the lane must stay silent on.
import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
const router = Router();

// A requiring identity middleware in the chain IS a guard.
router.get('/me/history', authenticate, async (req, res) => {
  const history = await db.query('SELECT * FROM games WHERE user_id = $1', [req.userId]);
  res.json(history);
});

// A write that uses the caller to scope its work is authorized, not merely authenticated.
router.post('/me/history', authenticate, async (req, res) => {
  await db.query('INSERT INTO games (user_id, pgn) VALUES ($1, $2)', [req.userId, req.body.pgn]);
  res.status(201).json({ ok: true });
});

export default router;
