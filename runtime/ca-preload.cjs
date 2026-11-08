'use strict';
// Applied before application code, even when Node uses its embedded roots.
const fs = require('node:fs');
const { apply } = require('./ca-image-filter.cjs');
apply(fs.readFileSync('/nodejs/lib/ca-image-exclusions.txt', 'utf8'));
// Keep the live mounted policy strictly additive to the baked exclusions.
if (process.env.MNR_CA_DISTRUST_FILE) require('./ca-distrust.cjs');
