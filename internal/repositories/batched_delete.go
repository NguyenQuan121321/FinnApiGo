package repositories

import (
	"gorm.io/gorm"
)

// purgeBatchSize caps each DELETE statement issued by the purge jobs so a
// backlog is nibbled away in short lock-holding statements instead of one
// giant transaction (P1). Var (not const) so tests can shrink it.
var purgeBatchSize = 1000

// batchedDelete deletes rows of the given model matching cond in
// LIMIT-batched statements until exhausted, returning the total removed.
// db must be a clean session (WithContext'd); each iteration chains from it.
func batchedDelete(db *gorm.DB, model any, cond string, arg any) (int64, error) {
	var total int64
	for {
		res := db.Where(cond, arg).Limit(purgeBatchSize).Delete(model)
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
		if res.RowsAffected < int64(purgeBatchSize) {
			return total, nil
		}
	}
}
