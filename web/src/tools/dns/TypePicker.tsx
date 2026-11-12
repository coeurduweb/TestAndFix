// Record type choice: the everyday types as segments, the rest in a list. Changing the type
// keeps the name: the caller navigates.
import { useId } from 'react';
import { t } from '../../lib/i18n';
import { COMMON_TYPES, TYPE_HINT } from './rrtypes';

export function TypePicker({
  value,
  types,
  onChange,
  label,
}: {
  value: string;
  types: readonly string[];
  onChange: (type: string) => void;
  label?: string;
}) {
  const id = useId();
  const common = COMMON_TYPES.filter((ty) => types.includes(ty));
  const others = types.filter((ty) => !(COMMON_TYPES as readonly string[]).includes(ty));
  const isOther = others.includes(value);
  return (
    <div className="rr-picker" role="group" aria-labelledby={`${id}-l`}>
      <span className="rr-picker__label" id={`${id}-l`}>
        {label ?? t('Type')}
      </span>
      <div className="segmented rr-seg">
        {common.map((ty) => (
          <button key={ty} type="button" aria-pressed={value === ty} onClick={() => value !== ty && onChange(ty)} title={t(TYPE_HINT[ty])}>
            {ty}
          </button>
        ))}
      </div>
      <label className="visually-hidden" htmlFor={`${id}-o`}>
        {t('Autre type')}
      </label>
      <select
        id={`${id}-o`}
        className={`select rr-other ${isOther ? 'rr-other--on' : ''}`}
        value={isOther ? value : ''}
        onChange={(e) => e.target.value && onChange(e.target.value)}
      >
        <option value="">{t('Autre type…')}</option>
        {others.map((ty) => (
          <option key={ty} value={ty}>
            {ty} : {t(TYPE_HINT[ty])}
          </option>
        ))}
      </select>
    </div>
  );
}
