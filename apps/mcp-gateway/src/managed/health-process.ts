import { observeManagedHealthSample } from "./health-observation.js";
import { runHealthObservationProcess } from "./health-observation/process.js";
import { localTimers } from "./stage-reader/fs.js";
import { ownHealthOutput } from "./health-observation/process-host.js";

// Fixed executable: no application/server, CLI options, alternate paths or
// remote endpoints. Fatal cleanup requires actual termination, not exitCode.
process.exitCode = await runHealthObservationProcess(process.argv.slice(2), process.env, observeManagedHealthSample, {
  ...ownHealthOutput(process.stdout, process.stderr),
  on: process.on.bind(process), removeListener: process.removeListener.bind(process), timers: localTimers,
  terminate: () => { process.exit(1); },
});
