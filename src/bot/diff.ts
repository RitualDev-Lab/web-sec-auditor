import type { DiffLineRange, ParsedDiffFile } from "./types.js";

/**
 * Parses unified diff text (standard git diff or GitHub PR diff) into structured file models
 * tracking exact line numbers added in the head revision.
 */
export function parseUnifiedDiff(diffText: string): ParsedDiffFile[] {
  const files: ParsedDiffFile[] = [];
  const lines = diffText.split("\n");

  let currentFile: ParsedDiffFile | null = null;
  let currentHunk: {
    header: string;
    lines: string[];
    range: DiffLineRange;
  } | null = null;
  let currentNewLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // File header: diff --git a/path b/path
    if (line.startsWith("diff --git ")) {
      if (currentFile) {
        if (currentHunk) {
          currentFile.hunks.push(currentHunk);
          currentHunk = null;
        }
        files.push(currentFile);
      }

      const match = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
      const oldPath = match ? match[1] : "";
      const newPath = match ? match[2] : "";

      currentFile = {
        oldPath,
        newPath,
        status: "modified",
        addedLines: [],
        hunks: [],
      };
      continue;
    }

    if (!currentFile) {
      continue;
    }

    // Detect new or deleted files
    if (line.startsWith("new file mode")) {
      currentFile.status = "added";
      continue;
    }
    if (line.startsWith("deleted file mode")) {
      currentFile.status = "deleted";
      continue;
    }

    // Hunk header: @@ -oldStart,oldCount +newStart,newCount @@ [optional heading]
    if (line.startsWith("@@ ")) {
      if (currentHunk) {
        currentFile.hunks.push(currentHunk);
      }

      const hunkMatch = line.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/);
      if (hunkMatch) {
        const oldStart = Number.parseInt(hunkMatch[1], 10);
        const oldCount = hunkMatch[2] ? Number.parseInt(hunkMatch[2], 10) : 1;
        const newStart = Number.parseInt(hunkMatch[3], 10);
        const newCount = hunkMatch[4] ? Number.parseInt(hunkMatch[4], 10) : 1;

        currentNewLine = newStart;
        currentHunk = {
          header: line,
          lines: [],
          range: { oldStart, oldCount, newStart, newCount },
        };
      }
      continue;
    }

    if (!currentHunk) {
      continue;
    }

    currentHunk.lines.push(line);

    if (line.startsWith("+") && !line.startsWith("+++")) {
      currentFile.addedLines.push(currentNewLine);
      currentNewLine++;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      // Deletions do not advance the new file line counter
    } else if (line.startsWith(" ")) {
      // Context lines exist in both old and new
      currentNewLine++;
    }
  }

  if (currentFile) {
    if (currentHunk) {
      currentFile.hunks.push(currentHunk);
    }
    files.push(currentFile);
  }

  return files;
}

/**
 * Checks if a specific 1-based line in a given file was added or modified in the diff.
 */
export function isLineInDiff(
  files: ParsedDiffFile[],
  filePath: string,
  lineNumber: number,
): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  const file = files.find(
    (f) =>
      f.newPath.replace(/\\/g, "/") === normalized || f.oldPath.replace(/\\/g, "/") === normalized,
  );

  if (!file) {
    return false;
  }

  return file.addedLines.includes(lineNumber);
}

/**
 * Checks if a specific filename or path was touched in the diff.
 */
export function isFileTouchedInDiff(
  files: ParsedDiffFile[],
  filePathPattern: string | RegExp,
): boolean {
  return files.some((f) => {
    const path = f.newPath || f.oldPath;
    if (typeof filePathPattern === "string") {
      return (
        path.toLowerCase().includes(filePathPattern.toLowerCase()) || path.endsWith(filePathPattern)
      );
    }
    return filePathPattern.test(path);
  });
}
