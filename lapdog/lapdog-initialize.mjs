import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { isMainThread } from "node:worker_threads";

if (isMainThread) {
    let tracerPath;

    // Check the entry script first, then the working directory if it cannot find dd-trace.
    const resolutionBases = [];
    if (process.argv[1]) resolutionBases.push(resolve(process.argv[1]));
    resolutionBases.push(resolve(process.cwd(), "package.json"));

    for (const base of resolutionBases) {
        try {
            tracerPath = createRequire(base).resolve("dd-trace/initialize.mjs");
            break;
        } catch (e) {
            if (e.code !== "MODULE_NOT_FOUND") {
                throw e;
            }
        }
    }

    if (tracerPath) {
        await import(pathToFileURL(tracerPath).href);
    } else {
        console.log(
            "[lapdog] dd-trace is not installed.\n" +
            "[lapdog] Please install it with:\n" +
            "[lapdog]   npm install dd-trace\n"
        );
    }
}
