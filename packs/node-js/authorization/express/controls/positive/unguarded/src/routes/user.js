// Every rule this pack binds must fire on this tree.
import { Router } from 'express';
const router = Router();

// Declared sensitive by the project and guarded by nothing at all.
router.get('/me/history', async (req, res) => {
  const history = await db.query('SELECT * FROM games WHERE user_id = $1', [req.query.id]);
  res.json(history);
});

export default router;
