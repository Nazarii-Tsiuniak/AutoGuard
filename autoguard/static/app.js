document.querySelector('.menu-button')?.addEventListener('click', function () {
  const open = document.querySelector('#navigation').classList.toggle('is-open');
  this.setAttribute('aria-expanded', String(open));
});
document.querySelectorAll('form[data-confirm]').forEach(form => {
  form.addEventListener('submit', event => { if (!confirm(form.dataset.confirm)) event.preventDefault(); });
});
document.querySelectorAll('#navigation a').forEach(link => {
  if (new URL(link.href).pathname === location.pathname) link.setAttribute('aria-current', 'page');
});
const strength = document.querySelector('#password-strength');
if (strength) document.querySelector('#password').addEventListener('input', event => {
  const p = event.target.value;
  strength.value = [p.length >= 8, /\p{Lu}/u.test(p), /\p{Ll}/u.test(p), /\p{N}/u.test(p), /[^\p{L}\p{N}\s]/u.test(p)].filter(Boolean).length;
  document.querySelector('#password-help').textContent = strength.value === 5 ? 'Пароль відповідає вимогам.' : '8+ символів, велика й мала літери, цифра та спецсимвол.';
});

document.querySelectorAll('[data-work-editor]').forEach(editor => {
  const rows = editor.querySelector('[data-work-rows]');
  const addButton = editor.querySelector('[data-add-work]');
  const updateRows = () => {
    const entries = [...rows.querySelectorAll('[data-work-row]')];
    entries.forEach((row, index) => {
      const input = row.querySelector('input');
      input.id = index === 0 ? 'work' : `work-${index + 1}`;
      input.setAttribute('aria-label', `Робота ${index + 1}`);
      input.required = index === 0;
      row.querySelector('[data-remove-work]').hidden = entries.length === 1;
    });
    addButton.disabled = entries.length >= 20;
  };
  addButton.addEventListener('click', () => {
    if (rows.children.length >= 20) return;
    const row = rows.firstElementChild.cloneNode(true);
    const input = row.querySelector('input');
    input.value = '';
    input.removeAttribute('value');
    rows.append(row);
    updateRows();
    input.focus();
  });
  rows.addEventListener('click', event => {
    const remove = event.target.closest('[data-remove-work]');
    if (!remove || rows.children.length <= 1) return;
    const row = remove.closest('[data-work-row]');
    const neighbour = row.nextElementSibling || row.previousElementSibling;
    row.remove();
    updateRows();
    neighbour.querySelector('input').focus();
  });
  updateRows();
});

// Native searchable dropdowns also allow a value outside the starter catalogue.
const suggestionFields = document.querySelectorAll('[data-autocomplete]');
if (suggestionFields.length) {
  const scriptURL = document.querySelector('script[src$="/app.js"]').src;
  fetch(new URL('form-options.json', scriptURL))
    .then(response => {
      if (!response.ok) throw new Error('Suggestions unavailable');
      return response.json();
    })
    .then(catalogue => {
      const normalize = value => value.trim().normalize('NFD').replace(/\p{M}/gu, '').toLocaleLowerCase('uk');
      const makes = Object.keys(catalogue.vehicles).sort((a, b) => a.localeCompare(b, 'uk'));
      const lists = new Map();
      suggestionFields.forEach(field => {
        const listId = field.dataset.autocomplete === 'work' ? 'work-suggestions' : `${field.id}-suggestions`;
        let list = document.getElementById(listId);
        if (!list) {
          list = document.createElement('datalist');
          list.id = listId;
          field.insertAdjacentElement('afterend', list);
        }
        field.setAttribute('list', list.id);
        lists.set(field.dataset.autocomplete, list);
        if (field.dataset.autocomplete === 'work') return;
        const hint = document.createElement('small');
        hint.id = `${field.id}-suggestion-help`;
        hint.textContent = field.dataset.autocomplete === 'model'
          ? 'Підказки для вибраної марки. Можна ввести власну модель.'
          : 'Почніть вводити для пошуку або введіть власний варіант.';
        field.parentElement.append(hint);
        field.setAttribute('aria-describedby', `${field.getAttribute('aria-describedby') || ''} ${hint.id}`.trim());
      });
      const fill = (kind, values) => {
        const list = lists.get(kind);
        if (!list) return;
        list.replaceChildren(...values.map(value => {
          const option = document.createElement('option');
          option.value = value;
          return option;
        }));
      };
      fill('make', makes);
      fill('work', catalogue.maintenance);
      const makeField = document.querySelector('[data-autocomplete="make"]');
      const modelField = document.querySelector('[data-autocomplete="model"]');
      if (makeField && modelField) {
        const updateModels = () => {
          const selected = normalize(makeField.value);
          // Common local spellings work for existing manually entered vehicles too.
          const aliases = { 'vw': 'volkswagen', 'фольксваген': 'volkswagen', 'шкода': 'skoda',
            'тойота': 'toyota', 'бмв': 'bmw', 'мерседес': 'mercedes-benz', 'mercedes': 'mercedes-benz',
            'ауді': 'audi', 'рено': 'renault', 'сітроен': 'citroen', 'заз': 'заз', 'zaz': 'заз' };
          const match = makes.find(make => normalize(make) === (aliases[selected] || selected));
          fill('model', match ? catalogue.vehicles[match] : []);
          modelField.placeholder = match ? `Почніть вводити модель ${match}` : 'Виберіть марку або введіть власну модель';
        };
        makeField.addEventListener('input', updateModels);
        makeField.addEventListener('change', updateModels);
        updateModels(); // Populate suggestions when editing an existing vehicle.
      }
    })
    .catch(() => { /* Manual input stays available if the catalogue cannot load. */ });
}
