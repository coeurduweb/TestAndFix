// Landing of the IP tool (v2 ToolHero) and the page shown when the address in the URL is not one.
// The hero takes one address; a range typed in it, or a list pasted (several lines), is routed to
// the range / list view before the hero's own check refuses it.
import { useEffect, type ClipboardEvent, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Network } from 'lucide-react';
import { Notice } from '../../components/ui';
import { ToolHero } from '../../components/ToolHero';
import { isIp } from '../../lib/detect';
import { t } from '../../lib/i18n';
import { expectedIps, inputPath, isRange, parseInput } from './model';

/** Why a typed value is not something this tool measures, or null when it is. */
export function invalidReason(tok: string): string | null {
  if (isIp(tok) || isRange(tok)) return null;
  const cidr = /^(.+)\/(\d{1,3})$/.exec(tok);
  if (cidr && isIp(cidr[1])) return cidr[1].includes(':') ? t('Les plages IPv6 ne sont pas mesurées : saisissez les adresses une par une.') : t('« /{prefix} » : seules les plages de /24 à /32 sont mesurées (256 adresses au plus).', { prefix: cidr[2] });
  if (/^\d+(\.\d+){3}$/.test(tok)) return t('« {value} » n’est pas une adresse IPv4 : chacun des quatre nombres va de 0 à 255.', { value: tok });
  return t('« {value} » n’est ni une adresse IP ni un nom de domaine. Exemple : 203.0.113.10, 203.0.113.0/24 ou exemple.fr.', { value: tok });
}

export function IpHero({ below = false }: { below?: boolean } = {}) {
  const navigate = useNavigate();
  // under a notice or a card, the hero's autofocus must not scroll the page past them
  useEffect(() => {
    if (below) requestAnimationFrame(() => window.scrollTo({ top: 0 }));
  }, [below]);
  const route = (raw: string): boolean => {
    const p = parseInput(raw);
    if (!p.items.length || (p.items.length === 1 && isIp(p.items[0]) && !p.invalid.length)) return false;
    if (expectedIps(p.items).length > 256) return false;
    const path = inputPath(p);
    if (!path) return false;
    navigate(path + (p.invalid.length && p.items.length > 1 ? `&ignorees=${p.invalid.map(encodeURIComponent).join(',')}` : ''));
    return true;
  };
  return (
    <div
      onPasteCapture={(e: ClipboardEvent<HTMLDivElement>) => {
        // a pasted list keeps its lines here: an <input> would glue them together
        const text = e.clipboardData.getData('text');
        if (/[\n,;]/.test(text.trim()) && route(text)) e.preventDefault();
      }}
      onSubmitCapture={(e: FormEvent<HTMLDivElement>) => {
        const input = (e.target as HTMLElement).querySelector('input');
        if (input && route(input.value)) {
          e.preventDefault();
          e.stopPropagation();
        }
      }}
    >
      <ToolHero
        icon={Network}
        title={t('Réputation')}
        desc={t('Cette IP ou ce domaine est-il sur une liste noire ? Listes interrogées en direct, et pour chaque inscription la procédure de retrait. Pour un domaine : ses listes de domaines, son âge, et la réputation des adresses de son site et de ses serveurs de mail. Une plage (/24 à /32) ou une liste d’IP collée marchent aussi.')}
        basePath="/ip"
        accept="domain-or-ip"
        label={t('Adresse IP, domaine, plage ou liste')}
        placeholder={t('8.8.8.8 ou exemple.fr')}
        examples={['8.8.8.8', 'gmail.com', '89.147.203.186']}
      />
    </div>
  );
}

/** An invalid address in the URL: nothing is measured, the hero says why. */
export function InvalidInput({ value, reason }: { value: string; reason: string }) {
  return (
    <div className="ipx-page">
      <Notice tone="warn" title={t('« {value} » ne peut pas être mesuré', { value: value.length > 60 ? value.slice(0, 57) + '…' : value })}>
        {reason} {t('Corrigez la saisie ci-dessous.')}
      </Notice>
      <IpHero below />
    </div>
  );
}
