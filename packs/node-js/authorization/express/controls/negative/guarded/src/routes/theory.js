import { Router } from 'express';
const router = Router();

// A declared-public route is a signed decision, not an omission. It also proves the
// word-boundary match: "middlegame" must not read as "game".
router.get('/categories', (_req, res) => {
  res.json([{ id: 'openings', label: 'Openings' }, { id: 'middlegame', label: 'Middlegame' }]);
});

export default router;
