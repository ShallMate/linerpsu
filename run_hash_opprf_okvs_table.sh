#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ROOT}/bazel-bin/examples/linerpsu/ourpsu"
OUT_DIR="${LINERPSU_OUT_DIR:-${ROOT}/examples/linerpsu/results/Ours/hash_opprf_okvs_$(date +%Y%m%d_%H%M%S)}"
SUMMARY="${OUT_DIR}/summary.csv"
TABLE="${OUT_DIR}/table.csv"
LOGNS="${LINERPSU_LOGNS:-18 20 22}"
BACKENDS="${LINERPSU_OKVS_BACKENDS:-okvs bandokvs}"
BUILD_FIRST="${LINERPSU_BUILD_FIRST:-1}"

mkdir -p "${OUT_DIR}"

if [[ "${BUILD_FIRST}" != "0" ]]; then
  bazel build //examples/linerpsu:ourpsu
fi

printf 'backend,backend_label,logn,ns,nr,cuckoolen,status,time_s,comm_bytes,comm_mb,sender_masks,receiver_masks,console_log\n' > "${SUMMARY}"

extract_value() {
  local line="$1"
  local key="$2"
  tr ',' '\n' <<< "${line}" | awk -F= -v k="${key}" '$1 == k {print $2; exit}'
}

backend_label() {
  case "$1" in
    okvs)
      printf 'Default'
      ;;
    bandokvs)
      printf 'With bpsy23'
      ;;
    *)
      printf '%s' "$1"
      ;;
  esac
}

run_case() {
  local backend="$1"
  local logn="$2"
  local label
  label="$(backend_label "${backend}")"
  local log_file="${OUT_DIR}/${backend}_logn${logn}.log"

  echo "[linerpsu] backend=${backend} logn=${logn}"
  set +e
  OMP_NUM_THREADS=1 \
  PSU_PEQT_GMW_THREADS=1 \
  PSU_PEQT_PARALLEL_BATCHES=1 \
  LINERPSU_RESULT_LINE=1 \
  LINERPSU_HASH_OPPRF_ONLY=1 \
  LINERPSU_OKVS_BACKEND="${backend}" \
  LINERPSU_LOGN="${logn}" \
  "${BIN}" > "${log_file}" 2>&1
  local status_code=$?
  set -e

  local result_line
  result_line="$(grep 'LINERPSU_HASH_OPPRF_RESULT' "${log_file}" | tail -n 1 || true)"
  local status="ok"
  if [[ ${status_code} -ne 0 || -z "${result_line}" ]]; then
    status="fail_${status_code}"
  fi

  local ns="" nr="" cuckoolen="" time_s="" comm_bytes="" comm_mb=""
  local sender_masks="" receiver_masks=""
  if [[ -n "${result_line}" ]]; then
    ns="$(extract_value "${result_line}" ns)"
    nr="$(extract_value "${result_line}" nr)"
    cuckoolen="$(extract_value "${result_line}" cuckoolen)"
    time_s="$(extract_value "${result_line}" time_s)"
    comm_bytes="$(extract_value "${result_line}" comm_bytes)"
    sender_masks="$(extract_value "${result_line}" sender_masks)"
    receiver_masks="$(extract_value "${result_line}" receiver_masks)"
    comm_mb="$(awk -v b="${comm_bytes}" 'BEGIN {printf "%.6f", b / 1048576.0}')"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "${backend}" "${label}" "${logn}" "${ns}" "${nr}" "${cuckoolen}" \
    "${status}" "${time_s}" "${comm_bytes}" "${comm_mb}" \
    "${sender_masks}" "${receiver_masks}" "${log_file}" >> "${SUMMARY}"

  if [[ "${status}" != "ok" ]]; then
    echo "[linerpsu] failed backend=${backend} logn=${logn}, see ${log_file}" >&2
  fi
}

lookup_summary() {
  local backend="$1"
  local logn="$2"
  local column="$3"
  awk -F, -v b="${backend}" -v n="${logn}" -v col="${column}" '
    NR == 1 {
      for (i = 1; i <= NF; ++i) {
        idx[$i] = i
      }
      next
    }
    $1 == b && $3 == n {
      print $idx[col]
      exit
    }
  ' "${SUMMARY}"
}

for backend in ${BACKENDS}; do
  for logn in ${LOGNS}; do
    run_case "${backend}" "${logn}"
  done
done

{
  printf 'construction,metric'
  for logn in ${LOGNS}; do
    printf ',2^%s' "${logn}"
  done
  printf '\n'

  for backend in ${BACKENDS}; do
    label="$(backend_label "${backend}")"
    printf '%s,Time (s)' "${label}"
    for logn in ${LOGNS}; do
      printf ',%s' "$(lookup_summary "${backend}" "${logn}" time_s)"
    done
    printf '\n'

    printf '%s,Communication (MB)' "${label}"
    for logn in ${LOGNS}; do
      printf ',%s' "$(lookup_summary "${backend}" "${logn}" comm_mb)"
    done
    printf '\n'
  done
} > "${TABLE}"

echo "[linerpsu] summary: ${SUMMARY}"
echo "[linerpsu] table: ${TABLE}"
