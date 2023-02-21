const fs = require('fs');
const path = require('path');
const { version } = require('../package.json');

const pomPath = path.join(__dirname, '../pom.xml');
const data = fs.readFileSync(pomPath);
const reg = new RegExp('<package.version>([^<]*)</package.version>');
console.log('version', version);
const xml = data
	.toString()
	.replace(reg, (match) => {
		console.log(match, version);
		return `<package.version>${version}</package.version>`;
	})
;

fs.writeFileSync(pomPath, xml);
